%%%----------------------------------------------------------------------
%%% File    : mod_antispam.erl
%%% Author  : Holger Weiss <holger@zedat.fu-berlin.de>
%%% Author  : Stefan Strigler <stefan@strigler.de>
%%% Purpose : Filter spam messages based on sender JID and content
%%% Created : 31 Mar 2019 by Holger Weiss <holger@zedat.fu-berlin.de>
%%%
%%%
%%% ejabberd, Copyright (C) 2019-2025 ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------

%%| definitions

-module(mod_antispam).
-author('holger@zedat.fu-berlin.de').
-author('stefan@strigler.de').

-behaviour(gen_server).
-behaviour(gen_mod).

%% gen_mod callbacks.
-export([start/2,
	 prep_stop/1,
	 stop/1,
	 reload/3,
	 depends/2,
	 mod_doc/0,
	 mod_opt_type/1,
	 mod_options/1]).

%% gen_server callbacks.
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3]).

%% ejabberd_commands callbacks.
-export([add_blocked_domain/2,
	 add_to_spam_filter_cache/2,
	 drop_from_spam_filter_cache/2,
	 expire_spam_filter_cache/2,
	 get_blocked_domains/1,
	 get_commands_spec/0,
	 get_spam_filter_cache/1,
	 reload_spam_filter_files/1,
	 remove_blocked_domain/2]).

-include_lib("xmpp/include/xmpp.hrl").
-include("ejabberd_commands.hrl").
-include("logger.hrl").
-include("mod_antispam.hrl").
-include("translate.hrl").

-define(COMMAND_TIMEOUT, timer:seconds(30)).
-define(DEFAULT_CACHE_SIZE, 10000).

%% @format-begin

%%--------------------------------------------------------------------
%%| gen_mod callbacks

-spec start(binary(), gen_mod:opts()) -> ok | {error, any()}.
start(Host, Opts) ->
    case gen_mod:is_loaded_elsewhere(Host, ?MODULE) of
        false ->
            ejabberd_commands:register_commands(?MODULE, get_commands_spec());
        true ->
            ok
    end,
    gen_mod:start_child(?MODULE, Host, Opts).

-spec prep_stop(binary()) -> ok | {error, any()}.
prep_stop(Host) ->
    case try_call_by_host(Host, prepare_stop) of
        ready_to_stop ->
            ok
    end.

-spec stop(binary()) -> ok | {error, any()}.
stop(Host) ->
    case gen_mod:is_loaded_elsewhere(Host, ?MODULE) of
        false ->
            ejabberd_commands:unregister_commands(get_commands_spec());
        true ->
            ok
    end,
    gen_mod:stop_child(?MODULE, Host).

-spec reload(binary(), gen_mod:opts(), gen_mod:opts()) -> ok.
reload(Host, NewOpts, OldOpts) ->
    ?DEBUG("reloading", []),
    Proc = get_proc_name(Host),
    gen_server:cast(Proc, {reload_module, NewOpts, OldOpts}).

-spec depends(binary(), gen_mod:opts()) -> [{module(), hard | soft}].
depends(_Host, _Opts) ->
    [{mod_pubsub, soft}].

-spec mod_opt_type(atom()) -> econf:validator().
mod_opt_type(access_spam) ->
    econf:acl();
mod_opt_type(cache_size) ->
    econf:pos_int(unlimited);
mod_opt_type(rtbl_services) ->
    econf:either(
        econf:bool(),
        econf:list(
            econf:and_then(
                econf:options(#{host => econf:binary(), node => econf:binary()}),
                fun(Opts) ->
                   #rtbl_service{host = proplists:get_value(host, Opts, <<>>),
                                 node = proplists:get_value(node, Opts, <<>>)}
                end)));
mod_opt_type(spam_domains_file) ->
    econf:either(
        econf:enum([none]), econf:file());
mod_opt_type(spam_dump_file) ->
    econf:either(
        econf:bool(), econf:file(write));
mod_opt_type(spam_jids_file) ->
    econf:either(
        econf:enum([none]), econf:file());
mod_opt_type(spam_urls_file) ->
    econf:either(
        econf:enum([none]), econf:file());
mod_opt_type(whitelist_domains_file) ->
    econf:either(
        econf:enum([none]), econf:file()).

-spec mod_options(binary()) -> [{rtbl_services, boolean() | [tuple()]} | {atom(), any()}].
mod_options(_Host) ->
    [{access_spam, none},
     {cache_size, ?DEFAULT_CACHE_SIZE},
     {rtbl_services, false},
     {spam_domains_file, none},
     {spam_dump_file, false},
     {spam_jids_file, none},
     {spam_urls_file, none},
     {whitelist_domains_file, none}].

mod_doc() ->
    #{desc =>
          ?T("Filter spam messages and subscription requests received from "
             "remote servers based on "
             "https://xmppbl.org/[Real-Time Block Lists (RTBL)], "
             "lists of known spammer JIDs and/or URLs mentioned in spam messages. "
             "Traffic classified as spam is rejected with an error "
             "(and an '[info]' message is logged) unless the sender "
             "is subscribed to the recipient's presence."),
      note => "added in 25.xx",
      opts =>
          [{access_spam,
            #{value => ?T("Access"),
              desc =>
                  ?T("Access rule that controls what accounts may receive spam messages. "
                     "If the rule returns 'allow' for a given recipient, "
                     "spam messages aren't rejected for that recipient. "
                     "The default value is 'none', which means that all recipients "
                     "are subject to spam filtering verification.")}},
           {cache_size,
            #{value => "pos_integer()",
              desc =>
                  ?T("Maximum number of JIDs that will be cached due to sending spam URLs. "
                     "If that limit is exceeded, the least recently used "
                     "entries are removed from the cache. "
                     "Setting this option to '0' disables the caching feature. "
                     "Note that separate caches are used for each virtual host, "
                     " and that the caches aren't distributed across cluster nodes. "
                     "The default value is '10000'.")}},
           {rtbl_services,
            #{value => ?T("false | true | [Service, ...]"),
              example =>
                  ["rtbl_services:",
                   "  -",
                   "    host: pubsub.server1.localhost",
                   "    node: spam1_source_domains",
                   "  -",
                   "    host: pubsub.server1.localhost",
                   "    node: muc_bans_sha256",
                   "  -",
                   "    host: pubsub.server2.localhost",
                   "    node: spam2_source_domains"],
              desc =>
                  ?T("List of RTBL services to query for domains to block. "
                     "If set to 'false', it doesn't query RTBL services, which is the default. "
                     "If set to 'true', it queries RTBL services provided by "
                     "https://xmppbl.org/[xmppbl.org]. "
                     "If set to a list of services, each service in the list "
                     "is constructed using the following options: ")},
            [{host,
              #{value => "string()", desc => ?T("Remote host with a PubSub service to query.")}},
             {node, #{value => "string()", desc => ?T("PubSub node to query.")}}]},
           {spam_domains_file,
            #{value => ?T("none | Path"),
              desc =>
                  ?T("Path to a plain text file containing a list of "
                     "known spam domains, one domain per line. "
                     "Messages and subscription requests sent from one of the listed domains "
                     "are classified as spam if sender is not in recipient's roster. "
                     "This list of domains gets merged with the one retrieved "
                     "by an RTBL host if any given. "
                     "The default value is 'none'.")}},
           {spam_dump_file,
            #{value => ?T("false | true | Path"),
              desc =>
                  ?T("Path to the file to store blocked messages. "
                     "Use an absolute path, or the '@LOG_PATH@' "
                     "https://docs.ejabberd.im/admin/configuration/file-format/#predefined-keywords[predefined keyword] "
                     "to store logs "
                     "in the same place that the other ejabberd log files. "
                     "If set to 'false', it doesn't dump stanzas, which is the default. "
                     "If set to 'true', it stores in '\"@LOG_PATH@/spam_dump_@HOST@.log\"'.")}},
           {spam_jids_file,
            #{value => ?T("none | Path"),
              desc =>
                  ?T("Path to a plain text file containing a list of "
                     "known spammer JIDs, one JID per line. "
                     "Messages and subscription requests sent from one of "
                     "the listed JIDs are classified as spam. "
                     "Messages containing at least one of the listed JIDs"
                     "are classified as spam as well. "
                     "Furthermore, the sender's JID will be cached, "
                     "so that future traffic originating from that JID will also be classified as spam. "
                     "The default value is 'none'.")}},
           {spam_urls_file,
            #{value => ?T("none | Path"),
              desc =>
                  ?T("Path to a plain text file containing a list of "
                     "URLs known to be mentioned in spam message bodies. "
                     "Messages containing at least one of the listed URLs are classified as spam. "
                     "Furthermore, the sender's JID will be cached, "
                     "so that future traffic originating from that JID will be classified as spam as well. "
                     "The default value is 'none'.")}},
           {whitelist_domains_file,
            #{value => ?T("none | Path"),
              desc =>
                  ?T("Path to a file containing a list of "
                     "domains to whitelist from being blocked, one per line. "
                     "If either it is in 'spam_domains_file' or more realistically "
                     "in a domain sent by a RTBL host (see option 'rtbl_services') "
                     "then this domain will be ignored and stanzas from there won't be blocked. "
                     "The default value is 'none'.")}}],
      example =>
          ["modules:",
           "  mod_antispam:",
           "    spam_dump_file: \"@LOG_PATH@/spam/host-@HOST@.log\"",
           "    spam_jids_file: \"@CONFIG_PATH@/spam_jids.txt\"",
           "    rtbl_services:",
           "      -",
           "        host: xmppbl.org",
           "        node: muc_bans_sha256"]}.

%%--------------------------------------------------------------------
%%| gen_server: init

-spec init(list()) -> {ok, antispam_state()} | {stop, term()}.
init([Host, Opts]) ->
    process_flag(trap_exit, true),
    RtblServices = get_rtbl_services_option(Opts),
    mod_antispam_files:init_files(Host),
    mod_antispam_filter:init_filtering(Host),
    mod_antispam_rtbl:add_hook(Host),
    mod_antispam_rtbl:request_blocked_domains(RtblServices, Host),
    #{jid := JIDsSet,
      url := URLsSet,
      domains := SpamDomainsSet,
      whitelist_domains := WhitelistDomains} =
        read_files(Host),
    InitState =
        #antispam_state{host = Host,
                        jid_set = JIDsSet,
                        url_set = URLsSet,
                        dump_fd = mod_antispam_dump:init_dumping(Host),
                        max_cache_size = gen_mod:get_opt(cache_size, Opts),
                        whitelist_domains = set_to_map(WhitelistDomains, false),
                        rtbl_services = RtblServices},
    {ok, update_blocked_domains_state({add, set_to_map(SpamDomainsSet)}, InitState)}.

%%--------------------------------------------------------------------
%%| gen_server: handle_call

-spec handle_call(term(), {pid(), term()}, antispam_state()) ->
                     {reply, {spam_filter, term()}, antispam_state()} | {noreply, antispam_state()}.
handle_call({check_from, From}, _From, #antispam_state{jid_set = JIDsSet} = State) ->
    {Result, State1} = filter_from(From, JIDsSet, State),
    {reply, {spam_filter, Result}, State1};
handle_call({check_body, URLs, JIDs, From},
            _From,
            #antispam_state{url_set = URLsSet, jid_set = JIDsSet} = State) ->
    {Result1, State1} = filter_body(URLs, URLsSet, From, State),
    {Result2, State2} = filter_body(JIDs, JIDsSet, From, State1),
    Result =
        if Result1 == spam ->
               Result1;
           true ->
               Result2
        end,
    {reply, {spam_filter, Result}, State2};
handle_call(reload_spam_files, _From, State) ->
    {Result, State1} = reload_files(State),
    {reply, {spam_filter, Result}, State1};
handle_call({expire_cache, Age}, _From, State) ->
    {Result, State1} = expire_cache(Age, State),
    {reply, {spam_filter, Result}, State1};
handle_call({add_to_cache, JID}, _From, State) ->
    {Result, State1} = add_to_cache(JID, State),
    {reply, {spam_filter, Result}, State1};
handle_call({drop_from_cache, JID}, _From, State) ->
    {Result, State1} = drop_from_cache(JID, State),
    {reply, {spam_filter, Result}, State1};
handle_call(get_cache, _From, #antispam_state{jid_cache = Cache} = State) ->
    {reply, {spam_filter, maps:to_list(Cache)}, State};
handle_call({add_blocked_domain, Domain}, _From, State) ->
    Txt = format("~s added to blocked domains", [Domain]),
    {reply,
     {spam_filter, {ok, Txt}},
     update_blocked_domains_state({add, #{Domain => true}}, State)};
handle_call({remove_blocked_domain, Domain}, _From, State) ->
    Txt = format("~s removed from blocked domains", [Domain]),
    {reply, {spam_filter, {ok, Txt}}, update_blocked_domains_state({remove, Domain}, State)};
handle_call(get_blocked_domains,
            _From,
            #antispam_state{blocked_domains = BlockedDomains,
                            whitelist_domains = WhitelistDomains} =
                State) ->
    {reply, {blocked_domains, maps:merge(BlockedDomains, WhitelistDomains)}, State};
handle_call({is_blocked_domain, Domain},
            _From,
            #antispam_state{blocked_domains = BlockedDomains,
                            whitelist_domains = WhitelistDomains} =
                State) ->
    Domains = maps:merge(BlockedDomains, WhitelistDomains),
    Result =
        case maps:get(Domain, Domains, false) of
            false ->
                %DomainSha = mod_antispam_filter:sha256(jid:encode(jid:tolower(jid:remove_resource(Domain)))),
                DomainSha = mod_antispam_filter:sha256(Domain),
                maps:get(DomainSha, Domains, false);
            true ->
                true
        end,
    {reply, Result, State};
handle_call(prepare_stop,
            _From,
            #antispam_state{host = Host, rtbl_services = RtblServices} = State) ->
    mod_antispam_rtbl:unsubscribe(RtblServices, Host),
    {reply, ready_to_stop, State};
handle_call(Request, From, State) ->
    ?ERROR_MSG("Got unexpected request from ~p: ~p", [From, Request]),
    {noreply, State}.

%%--------------------------------------------------------------------
%%| gen_server: handle_cast

-spec handle_cast(term(), antispam_state()) -> {noreply, antispam_state()}.
handle_cast({dump_stanza, XML}, #antispam_state{dump_fd = Fd} = State) ->
    mod_antispam_dump:write_stanza_dump(Fd, XML),
    {noreply, State};
handle_cast(reopen_log, #antispam_state{host = Host, dump_fd = Fd} = State) ->
    {noreply, State#antispam_state{dump_fd = mod_antispam_dump:reopen_dump_file(Host, Fd)}};
handle_cast({reload_module, NewOpts, OldOpts},
            #antispam_state{host = Host, dump_fd = Fd} = State) ->
    RtblServices = get_rtbl_services_option(NewOpts),
    mod_antispam_rtbl:cancel_timers(RtblServices),
    mod_antispam_rtbl:unsubscribe(RtblServices, Host),
    mod_antispam_rtbl:request_blocked_domains(RtblServices, Host),
    State1 =
        State#antispam_state{dump_fd =
                                 mod_antispam_dump:reload_dumping(Host, Fd, OldOpts, NewOpts)},
    State2 =
        case {gen_mod:get_opt(cache_size, OldOpts), gen_mod:get_opt(cache_size, NewOpts)} of
            {OldMax, NewMax} when NewMax < OldMax ->
                shrink_cache(State1#antispam_state{max_cache_size = NewMax});
            {OldMax, NewMax} when NewMax > OldMax ->
                State1#antispam_state{max_cache_size = NewMax};
            {_OldMax, _NewMax} ->
                State1
        end,
    {_Result, State3} = reload_files(update_blocked_domains_state(clean_all, State2)),
    {noreply, State3#antispam_state{rtbl_services = RtblServices}};
handle_cast({update_blocked_domains, RHost, Node, NewItems},
            #antispam_state{rtbl_services = Services} = State) ->
    NewDomains =
        case mod_antispam_rtbl:get_service(RHost, Node, Services) of
            error_finding_service ->
                ?ERROR_MSG("Will not update blocked domains from unknown RTBL service (host ~p, node ~p)",
                           [RHost, Node]),
                #{};
            #rtbl_service{} ->
                NewItems
        end,
    {noreply, update_blocked_domains_state({add, NewDomains}, State)};
handle_cast(Request, State) ->
    ?ERROR_MSG("Got unexpected request from: ~p", [Request]),
    {noreply, State}.

%%--------------------------------------------------------------------
%%| gen_server: handle_info

-spec handle_info(term(), antispam_state()) -> {noreply, antispam_state()}.
handle_info({iq_reply, IQ, Atom}, State) ->
    {noreply, mod_antispam_rtbl:handle_iq_reply(IQ, Atom, State)};
handle_info(request_blocked_domains,
            #antispam_state{host = Host, rtbl_services = RtblServices} = State) ->
    mod_antispam_rtbl:request_blocked_domains(RtblServices, Host),
    {noreply, State};
handle_info(Info, State) ->
    ?ERROR_MSG("Got unexpected info: ~p", [Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%%| gen_server: terminate

-spec terminate(normal | shutdown | {shutdown, term()} | term(), antispam_state()) -> ok.
terminate(Reason,
          #antispam_state{host = Host,
                          dump_fd = Fd,
                          rtbl_services = RtblServices} =
              _State) ->
    ?DEBUG("Stopping spam filter process for ~s: ~p", [Host, Reason]),
    mod_antispam_dump:terminate_dumping(Host, Fd),
    mod_antispam_files:terminate_files(Host),
    mod_antispam_filter:terminate_filtering(Host),
    mod_antispam_rtbl:cancel_timers(RtblServices),
    mod_antispam_rtbl:delete_hook(Host),
    ok.

%%--------------------------------------------------------------------
%%| gen_server: code_change

-spec code_change({down, term()} | term(), antispam_state(), term()) ->
                     {ok, antispam_state()}.
code_change(_OldVsn, #antispam_state{host = Host} = State, _Extra) ->
    ?DEBUG("Updating spam filter process for ~s", [Host]),
    {ok, State}.

%%--------------------------------------------------------------------
%%| Filter

-spec filter_from(ljid(), jid_set(), antispam_state()) -> {ham | spam, antispam_state()}.
filter_from(From, Set, State) ->
    case sets:is_element(From, Set) of
        true ->
            {spam, State};
        false ->
            case cache_lookup(From, State) of
                {true, State1} ->
                    {spam, State1};
                {false, State1} ->
                    {ham, State1}
            end
    end.

-spec filter_body({urls, [url()]} | {jids, [ljid()]} | none,
                  url_set() | jid_set(),
                  jid(),
                  antispam_state()) ->
                     {ham | spam, antispam_state()}.
filter_body({_, Addrs}, Set, From, State) ->
    case lists:any(fun(Addr) -> sets:is_element(Addr, Set) end, Addrs) of
        true ->
            {spam, cache_insert(From, State)};
        false ->
            {ham, State}
    end;
filter_body(none, _Set, _From, State) ->
    {ham, State}.

%%--------------------------------------------------------------------
%%| Text files

-spec reload_files(antispam_state()) -> {ok | {error, binary()}, antispam_state()}.
reload_files(#antispam_state{host = Host} = State) ->
    case read_files(Host) of
        #{jid := JIDsSet,
          url := URLsSet,
          domains := SpamDomainsSet,
          whitelist_domains := WhitelistDomains} ->
            case sets_equal(JIDsSet, State#antispam_state.jid_set) of
                true ->
                    ?INFO_MSG("Reloaded spam JIDs for ~s (unchanged)", [Host]);
                false ->
                    ?INFO_MSG("Reloaded spam JIDs for ~s (changed)", [Host])
            end,
            case sets_equal(URLsSet, State#antispam_state.url_set) of
                true ->
                    ?INFO_MSG("Reloaded spam URLs for ~s (unchanged)", [Host]);
                false ->
                    ?INFO_MSG("Reloaded spam URLs for ~s (changed)", [Host])
            end,
            State2 = update_blocked_domains_state({add, set_to_map(SpamDomainsSet)}, State),
            {ok,
             State2#antispam_state{jid_set = JIDsSet,
                                   url_set = URLsSet,
                                   whitelist_domains = set_to_map(WhitelistDomains, false)}};
        {config_error, ErrorText} ->
            {{error, ErrorText}, State}
    end.

-spec sets_equal(sets:set(), sets:set()) -> boolean().
sets_equal(A, B) ->
    sets:is_subset(A, B) andalso sets:is_subset(B, A).

set_to_map(Set) ->
    set_to_map(Set, true).

set_to_map(Set, V) ->
    sets:fold(fun(K, M) -> M#{K => V} end, #{}, Set).

read_files(Host) ->
    AccInitial =
        #{jid => sets:new(),
          url => sets:new(),
          domains => sets:new(),
          whitelist_domains => sets:new()},
    Files =
        #{jid => gen_mod:get_module_opt(Host, ?MODULE, spam_jids_file),
          url => gen_mod:get_module_opt(Host, ?MODULE, spam_urls_file),
          domains => gen_mod:get_module_opt(Host, ?MODULE, spam_domains_file),
          whitelist_domains => gen_mod:get_module_opt(Host, ?MODULE, whitelist_domains_file)},
    ejabberd_hooks:run_fold(antispam_get_lists, Host, AccInitial, [Files]).

%%--------------------------------------------------------------------
%%| Auxiliary functions

update_blocked_domains_state(Operation,
                             #antispam_state{host = Host, blocked_domains = BlockedDomains} =
                                 State) ->
    NewDomains =
        case Operation of
            clean_all ->
                #{};
            {add, AddDomains} ->
                mod_antispam_filter:notify_rooms(Host, AddDomains),
                maps:merge(BlockedDomains, AddDomains);
            {remove, RemoveDomain} ->
                maps:remove(RemoveDomain, BlockedDomains)
        end,
    State#antispam_state{blocked_domains = NewDomains}.

get_rtbl_services_option(Opts) ->
    case gen_mod:get_opt(rtbl_services, Opts) of
        false ->
            [];
        true ->
            [#rtbl_service{host = <<"xmppbl.org">>, node = <<"muc_bans_sha256">>},
             #rtbl_service{host = <<"xmppbl.org">>, node = <<"spam_source_domains">>}];
        Services when is_list(Services) ->
            Services
    end.

-spec get_proc_name(binary()) -> atom().
get_proc_name(Host) ->
    gen_mod:get_module_proc(Host, ?MODULE).

-spec format(io:format(), [term()]) -> binary().
format(Format, Data) ->
    iolist_to_binary(io_lib:format(Format, Data)).

%%--------------------------------------------------------------------
%%| Caching

-spec cache_insert(ljid(), antispam_state()) -> antispam_state().
cache_insert(_LJID, #antispam_state{max_cache_size = 0} = State) ->
    State;
cache_insert(LJID, #antispam_state{jid_cache = Cache, max_cache_size = MaxSize} = State)
    when MaxSize /= unlimited, map_size(Cache) >= MaxSize ->
    cache_insert(LJID, shrink_cache(State));
cache_insert(LJID, #antispam_state{jid_cache = Cache} = State) ->
    ?INFO_MSG("Caching spam JID: ~s", [jid:encode(LJID)]),
    Cache1 = Cache#{LJID => erlang:monotonic_time(second)},
    State#antispam_state{jid_cache = Cache1}.

-spec cache_lookup(ljid(), antispam_state()) -> {boolean(), antispam_state()}.
cache_lookup(LJID, #antispam_state{jid_cache = Cache} = State) ->
    case Cache of
        #{LJID := _Timestamp} ->
            Cache1 = Cache#{LJID => erlang:monotonic_time(second)},
            State1 = State#antispam_state{jid_cache = Cache1},
            {true, State1};
        #{} ->
            {false, State}
    end.

-spec shrink_cache(antispam_state()) -> antispam_state().
shrink_cache(#antispam_state{jid_cache = Cache, max_cache_size = MaxSize} = State) ->
    ShrinkedSize = round(MaxSize / 2),
    N = map_size(Cache) - ShrinkedSize,
    L = lists:keysort(2, maps:to_list(Cache)),
    Cache1 =
        maps:from_list(
            lists:nthtail(N, L)),
    State#antispam_state{jid_cache = Cache1}.

-spec expire_cache(integer(), antispam_state()) -> {{ok, binary()}, antispam_state()}.
expire_cache(Age, #antispam_state{jid_cache = Cache} = State) ->
    Threshold = erlang:monotonic_time(second) - Age,
    Cache1 = maps:filter(fun(_, TS) -> TS >= Threshold end, Cache),
    NumExp = map_size(Cache) - map_size(Cache1),
    Txt = format("Expired ~B cache entries", [NumExp]),
    {{ok, Txt}, State#antispam_state{jid_cache = Cache1}}.

-spec add_to_cache(ljid(), antispam_state()) -> {{ok, binary()}, antispam_state()}.
add_to_cache(LJID, State) ->
    State1 = cache_insert(LJID, State),
    Txt = format("~s added to cache", [jid:encode(LJID)]),
    {{ok, Txt}, State1}.

-spec drop_from_cache(ljid(), antispam_state()) -> {{ok, binary()}, antispam_state()}.
drop_from_cache(LJID, #antispam_state{jid_cache = Cache} = State) ->
    Cache1 = maps:remove(LJID, Cache),
    if map_size(Cache1) < map_size(Cache) ->
           Txt = format("~s removed from cache", [jid:encode(LJID)]),
           {{ok, Txt}, State#antispam_state{jid_cache = Cache1}};
       true ->
           Txt = format("~s wasn't cached", [jid:encode(LJID)]),
           {{ok, Txt}, State}
    end.

%%--------------------------------------------------------------------
%%| ejabberd command callbacks

-spec get_commands_spec() -> [ejabberd_commands()].
get_commands_spec() ->
    [#ejabberd_commands{name = reload_spam_filter_files,
                        tags = [filter],
                        desc = "Reload spam JID/URL files",
                        module = ?MODULE,
                        function = reload_spam_filter_files,
                        args = [{host, binary}],
                        result = {res, rescode}},
     #ejabberd_commands{name = get_spam_filter_cache,
                        tags = [filter],
                        desc = "Show spam filter cache contents",
                        module = ?MODULE,
                        function = get_spam_filter_cache,
                        args = [{host, binary}],
                        result =
                            {spammers,
                             {list, {spammer, {tuple, [{jid, string}, {timestamp, integer}]}}}}},
     #ejabberd_commands{name = expire_spam_filter_cache,
                        tags = [filter],
                        desc = "Remove old/unused spam JIDs from cache",
                        module = ?MODULE,
                        function = expire_spam_filter_cache,
                        args = [{host, binary}, {seconds, integer}],
                        result = {res, restuple}},
     #ejabberd_commands{name = add_to_spam_filter_cache,
                        tags = [filter],
                        desc = "Add JID to spam filter cache",
                        module = ?MODULE,
                        function = add_to_spam_filter_cache,
                        args = [{host, binary}, {jid, binary}],
                        result = {res, restuple}},
     #ejabberd_commands{name = drop_from_spam_filter_cache,
                        tags = [filter],
                        desc = "Drop JID from spam filter cache",
                        module = ?MODULE,
                        function = drop_from_spam_filter_cache,
                        args = [{host, binary}, {jid, binary}],
                        result = {res, restuple}},
     #ejabberd_commands{name = get_blocked_domains,
                        tags = [filter],
                        desc = "Get list of domains being blocked",
                        module = ?MODULE,
                        function = get_blocked_domains,
                        args = [{host, binary}],
                        result = {blocked_domains, {list, {jid, string}}}},
     #ejabberd_commands{name = add_blocked_domain,
                        tags = [filter],
                        desc = "Add domain to list of blocked domains",
                        module = ?MODULE,
                        function = add_blocked_domain,
                        args = [{host, binary}, {domain, binary}],
                        result = {res, restuple}},
     #ejabberd_commands{name = remove_blocked_domain,
                        tags = [filter],
                        desc = "Remove domain from list of blocked domains",
                        module = ?MODULE,
                        function = remove_blocked_domain,
                        args = [{host, binary}, {domain, binary}],
                        result = {res, restuple}}].

for_all_hosts(F, A) ->
    try lists:map(fun(Host) -> apply(F, [Host | A]) end, get_spam_filter_hosts()) of
        List ->
            case lists:filter(fun ({error, _}) ->
                                      true;
                                  (_) ->
                                      false
                              end,
                              List)
            of
                [] ->
                    hd(List);
                Errors ->
                    hd(Errors)
            end
    catch
        error:{badmatch, {error, _Reason} = Error} ->
            Error
    end.

-spec get_spam_filter_hosts() -> [binary()].
get_spam_filter_hosts() ->
    [H || H <- ejabberd_option:hosts(), gen_mod:is_loaded(H, ?MODULE)].

try_call_by_host(Host, Call) ->
    LServer = jid:nameprep(Host),
    Proc = get_proc_name(LServer),
    try gen_server:call(Proc, Call, ?COMMAND_TIMEOUT) of
        Result ->
            Result
    catch
        exit:{noproc, _} ->
            {error, "Not configured for " ++ binary_to_list(Host)};
        exit:{timeout, _} ->
            {error, "Timeout while querying ejabberd"}
    end.

-spec reload_spam_filter_files(binary()) -> ok | {error, string()}.
reload_spam_filter_files(<<"global">>) ->
    for_all_hosts(fun reload_spam_filter_files/1, []);
reload_spam_filter_files(Host) ->
    case try_call_by_host(Host, reload_spam_files) of
        {spam_filter, ok} ->
            ok;
        {spam_filter, {error, Txt}} ->
            {error, Txt};
        {error, _R} = Error ->
            Error
    end.

-spec get_blocked_domains(binary()) -> [binary()].
get_blocked_domains(Host) ->
    case try_call_by_host(Host, get_blocked_domains) of
        {blocked_domains, BlockedDomains} ->
            maps:keys(
                maps:filter(fun (_, false) ->
                                    false;
                                (_, _) ->
                                    true
                            end,
                            BlockedDomains));
        {error, _R} = Error ->
            Error
    end.

-spec add_blocked_domain(binary(), binary()) -> {ok, string()}.
add_blocked_domain(<<"global">>, Domain) ->
    for_all_hosts(fun add_blocked_domain/2, [Domain]);
add_blocked_domain(Host, Domain) ->
    case try_call_by_host(Host, {add_blocked_domain, Domain}) of
        {spam_filter, {Status, Txt}} ->
            {Status, binary_to_list(Txt)};
        {error, _R} = Error ->
            Error
    end.

-spec remove_blocked_domain(binary(), binary()) -> {ok, string()}.
remove_blocked_domain(<<"global">>, Domain) ->
    for_all_hosts(fun remove_blocked_domain/2, [Domain]);
remove_blocked_domain(Host, Domain) ->
    case try_call_by_host(Host, {remove_blocked_domain, Domain}) of
        {spam_filter, {Status, Txt}} ->
            {Status, binary_to_list(Txt)};
        {error, _R} = Error ->
            Error
    end.

-spec get_spam_filter_cache(binary()) -> [{binary(), integer()}] | {error, string()}.
get_spam_filter_cache(Host) ->
    case try_call_by_host(Host, get_cache) of
        {spam_filter, Cache} ->
            [{jid:encode(JID), TS + erlang:time_offset(second)} || {JID, TS} <- Cache];
        {error, _R} = Error ->
            Error
    end.

-spec expire_spam_filter_cache(binary(), integer()) -> {ok | error, string()}.
expire_spam_filter_cache(<<"global">>, Age) ->
    for_all_hosts(fun expire_spam_filter_cache/2, [Age]);
expire_spam_filter_cache(Host, Age) ->
    case try_call_by_host(Host, {expire_cache, Age}) of
        {spam_filter, {Status, Txt}} ->
            {Status, binary_to_list(Txt)};
        {error, _R} = Error ->
            Error
    end.

-spec add_to_spam_filter_cache(binary(), binary()) ->
                                  [{binary(), integer()}] | {error, string()}.
add_to_spam_filter_cache(<<"global">>, JID) ->
    for_all_hosts(fun add_to_spam_filter_cache/2, [JID]);
add_to_spam_filter_cache(Host, EncJID) ->
    try jid:decode(EncJID) of
        #jid{} = JID ->
            LJID =
                jid:remove_resource(
                    jid:tolower(JID)),
            case try_call_by_host(Host, {add_to_cache, LJID}) of
                {spam_filter, {Status, Txt}} ->
                    {Status, binary_to_list(Txt)};
                {error, _R} = Error ->
                    Error
            end
    catch
        _:{bad_jid, _} ->
            {error, "Not a valid JID: " ++ binary_to_list(EncJID)}
    end.

-spec drop_from_spam_filter_cache(binary(), binary()) -> {ok | error, string()}.
drop_from_spam_filter_cache(<<"global">>, JID) ->
    for_all_hosts(fun drop_from_spam_filter_cache/2, [JID]);
drop_from_spam_filter_cache(Host, EncJID) ->
    try jid:decode(EncJID) of
        #jid{} = JID ->
            LJID =
                jid:remove_resource(
                    jid:tolower(JID)),
            case try_call_by_host(Host, {drop_from_cache, LJID}) of
                {spam_filter, {Status, Txt}} ->
                    {Status, binary_to_list(Txt)};
                {error, _R} = Error ->
                    Error
            end
    catch
        _:{bad_jid, _} ->
            {error, "Not a valid JID: " ++ binary_to_list(EncJID)}
    end.

%%--------------------------------------------------------------------

%%| vim: set foldmethod=marker foldmarker=%%|,%%-:
