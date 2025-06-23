%%%----------------------------------------------------------------------
%%% File    : mod_antispam_rtbl.erl
%%% Author  : Stefan Strigler <stefan@strigler.de>
%%% Purpose : Collection of RTBL specific functionality
%%% Created : 20 Mar 2025 by Stefan Strigler <stefan@strigler.de>
%%%
%%%
%%% ejabberd, Copyright (C) 2025 ProcessOne
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
%% @format-begin

-module(mod_antispam_rtbl).

-author('stefan@strigler.de').

-include_lib("xmpp/include/xmpp.hrl").

-include("logger.hrl").
-include("mod_antispam.hrl").

-define(SERVICE_MODULE, mod_antispam).
-define(SERVICE_JID_PREFIX, "rtbl-").

-export([request_blocked_domains/2, cancel_timers/1, handle_iq_reply/3, unsubscribe/2,
         get_service/3]).
%% Hooks
-export([add_hook/1, delete_hook/1, pubsub_event_handler/1]).

%%--------------------------------------------------------------------
%%| Route IQs

subscribe(#rtbl_service{host = Host, node = Node}, From) ->
    FromJID = service_jid(From),
    SubIQ =
        #iq{type = set,
            to = jid:make(Host),
            from = FromJID,
            sub_els = [#pubsub{subscribe = #ps_subscribe{jid = FromJID, node = Node}}]},
    ?DEBUG("Sending subscription request:~n~p", [xmpp:encode(SubIQ)]),
    ejabberd_router:route_iq(SubIQ, subscribe_result, self()).

-spec service_jid(binary()) -> jid().
service_jid(Host) ->
    jid:make(<<>>, Host, <<?SERVICE_JID_PREFIX, (ejabberd_cluster:node_id())/binary>>).

-spec unsubscribe([rtbl_service()] | rtbl_service(), binary()) -> ok.
unsubscribe(Services, From) when is_list(Services) ->
    [unsubscribe(Service, From) || Service <- Services];
unsubscribe(#rtbl_service{host = Host, node = Node}, From) ->
    FromJID = jid:make(From),
    SubIQ =
        #iq{type = set,
            to = jid:make(Host),
            from = FromJID,
            sub_els = [#pubsub{unsubscribe = #ps_unsubscribe{jid = FromJID, node = Node}}]},
    ejabberd_router:route_iq(SubIQ, unsubscribe_result, self()).

-spec request_blocked_domains([rtbl_service()] | rtbl_service(), binary()) -> any().
request_blocked_domains(Services, From) when is_list(Services) ->
    [request_blocked_domains(Service, From) || Service <- Services];
request_blocked_domains(#rtbl_service{host = Host, node = Node}, From) ->
    IQ = #iq{type = get,
             from = jid:make(From),
             to = jid:make(Host),
             sub_els = [#pubsub{items = #ps_items{node = Node}}]},
    ?DEBUG("Requesting RTBL blocked domains from ~s:~n~p", [Host, xmpp:encode(IQ)]),
    ejabberd_router:route_iq(IQ, blocked_domains, self()).

-spec cancel_timers([rtbl_service()]) -> any().
cancel_timers(Services) ->
    [misc:cancel_timer(RetryTimer) || #rtbl_service{retry_timer = RetryTimer} <- Services].

%%--------------------------------------------------------------------
%%| Parse

-spec parse_blocked_domains(stanza()) ->
                               {binary(), binary(), #{binary() => any()}} | undefined.
parse_blocked_domains(#iq{from = #jid{lserver = Host}, type = result} = IQ) ->
    ?DEBUG("parsing iq-result items: ~p", [IQ]),
    case xmpp:get_subtag(IQ, #pubsub{}) of
        #pubsub{items = #ps_items{node = Node, items = Items}} ->
            ?DEBUG("Got items:~n~p", [Items]),
            {Host, Node, parse_items(Items)};
        _ ->
            undefined
    end.

-spec parse_pubsub_event(stanza()) -> {binary(), binary(), #{binary() => any()}}.
parse_pubsub_event(#message{from = FromJid} = Msg) ->
    case xmpp:get_subtag(Msg, #ps_event{}) of
        #ps_event{items =
                      #ps_items{node = Node,
                                items = Items,
                                retract = RetractIds}} ->
            {jid:encode(FromJid), Node, maps:merge(retract_items(RetractIds), parse_items(Items))};
        Other ->
            ?WARNING_MSG("Couldn't extract items: ~p", [Other]),
            #{}
    end.

-spec parse_items([ps_item()]) -> #{binary() => any()}.
parse_items(Items) ->
    lists:foldl(fun(#ps_item{id = ID}, Acc) ->
                   %% TODO extract meta/extra instructions
                   maps:put(ID, true, Acc)
                end,
                #{},
                Items).

-spec retract_items([binary()]) -> #{binary() => false}.
retract_items(Ids) ->
    lists:foldl(fun(ID, Acc) -> Acc#{ID => false} end, #{}, Ids).

%%--------------------------------------------------------------------
%%| Handle iq_reply

%% TODO: How to know the host and node when timeout?
%% handle_iq_reply(timeout, blocked_domains, State) ->
%%     ?WARNING_MSG("Fetching blocked domains failed: fetch timeout. Retrying in 60 seconds",
%%                  []),
%%     State#antispam_state{rtbl_retry_timer = erlang:send_after(60000, self(), request_blocked_domains)};
handle_iq_reply(#iq{type = error, from = #jid{lserver = RHost}} = IQ,
                blocked_domains,
                #antispam_state{rtbl_services = Services} = State) ->
    ?WARNING_MSG("Fetching blocked domains failed: ~s. Retrying in 60 seconds",
                 [xmpp:format_stanza_error(
                      xmpp:get_error(IQ))]),
    #pubsub{items = #ps_items{node = Node}} = xmpp:get_subtag(IQ, #pubsub{}),
    NewTimer = erlang:send_after(60000, self(), request_blocked_domains),
    Services2 =
        update_service(Services, RHost, Node, [{#rtbl_service.retry_timer, NewTimer}]),
    State#antispam_state{rtbl_services = Services2};
handle_iq_reply(#iq{from = #jid{lserver = RHost}} = IQ,
                blocked_domains,
                #antispam_state{blocked_domains = OldBlockedDomains,
                                rtbl_services = Services,
                                host = OurHost} =
                    State) ->
    case parse_blocked_domains(IQ) of
        undefined ->
            ?WARNING_MSG("Fetching initial list failed: invalid result payload", []),
            %% TODO: How to know the pubsub node when there's a problem parsing payload?
            #pubsub{items = #ps_items{node = Node}} = xmpp:get_subtag(IQ, #pubsub{}),
            Services2 =
                update_service(Services, RHost, Node, [{#rtbl_service.retry_timer, undefined}]),
            State#antispam_state{rtbl_services = Services2};
        {RHost, Node, NewBlockedDomains} ->
            Services2 =
                update_service(Services,
                               RHost,
                               Node,
                               [{#rtbl_service.retry_timer, undefined},
                                {#rtbl_service.subscribed, true}]),
            ok = subscribe(get_service(RHost, Node, Services2), OurHost),
            State#antispam_state{rtbl_services = Services2,
                                 blocked_domains = maps:merge(OldBlockedDomains, NewBlockedDomains)}
    end;
%% TODO: How to know the host and node when timeout?
%% handle_iq_reply(timeout, subscribe_result, State) ->
%%     ?WARNING_MSG("Subscription error: request timeout", []),
%%     State#antispam_state{rtbl_subscribed = false};
handle_iq_reply(#iq{type = error, from = #jid{lserver = RHost}} = IQ,
                subscribe_result,
                #antispam_state{rtbl_services = Services} = State) ->
    ?WARNING_MSG("Subscription error: ~p",
                 [xmpp:format_stanza_error(
                      xmpp:get_error(IQ))]),
    #pubsub{subscribe = #ps_subscribe{node = Node}} = xmpp:get_subtag(IQ, #pubsub{}),
    Services2 = update_service(Services, RHost, Node, [{#rtbl_service.subscribed, true}]),
    State#antispam_state{rtbl_services = Services2};
handle_iq_reply(#iq{from = #jid{lserver = RHost}} = IQ,
                subscribe_result,
                #antispam_state{rtbl_services = Services} = State) ->
    ?DEBUG("Got subscribe result: ~p", [IQ]),
    #pubsub{subscription = #ps_subscription{node = Node}} = xmpp:get_subtag(IQ, #pubsub{}),
    Services2 = update_service(Services, RHost, Node, [{#rtbl_service.subscribed, true}]),
    State#antispam_state{rtbl_services = Services2};
handle_iq_reply(#iq{from = #jid{lserver = RHost}} = IQ,
                unsubscribe_result,
                #antispam_state{rtbl_services = Services} = State) ->
    %% FIXME: we should check it's true (of type `result`, not `error`), but at that point, what
    %% would we do?
    #pubsub{unsubscribe = #ps_unsubscribe{node = Node}} = xmpp:get_subtag(IQ, #pubsub{}),
    Services2 = update_service(Services, RHost, Node, [{#rtbl_service.subscribed, false}]),
    State#antispam_state{rtbl_services = Services2}.

get_service(Host, Node, Services) ->
    case split_services(Host, Node, Services) of
        {[S], _} ->
            S;
        _ ->
            error_finding_service
    end.

update_service(Services, Host, Node, Changes) ->
    Service = get_service(Host, Node, Services),
    NewService =
        lists:foldl(fun({Index, Value}, S) -> setelement(Index, S, Value) end, Service, Changes),
    {[_], RemainingServices} = split_services(Host, Node, Services),
    [NewService | RemainingServices].

split_services(Host, Node, Services) ->
    lists:partition(fun(S) -> (Host == S#rtbl_service.host) and (Node == S#rtbl_service.node)
                    end,
                    Services).

%%--------------------------------------------------------------------
%%| Hooks

add_hook(Host) ->
    ejabberd_hooks:add(local_send_to_resource_hook, Host, ?MODULE, pubsub_event_handler, 50).

delete_hook(Host) ->
    ejabberd_hooks:delete(local_send_to_resource_hook,
                          Host,
                          ?MODULE,
                          pubsub_event_handler,
                          50).

-spec pubsub_event_handler(stanza()) -> drop | stanza().
pubsub_event_handler(#message{to =
                                  #jid{lserver = LServer,
                                       lresource = <<?SERVICE_JID_PREFIX, _/binary>>}} =
                         Msg) ->
    ?DEBUG("Got RTBL message:~n~p", [Msg]),
    {Host, Node, ParsedItems} = parse_pubsub_event(Msg),
    Proc = gen_mod:get_module_proc(LServer, ?SERVICE_MODULE),
    gen_server:cast(Proc, {update_blocked_domains, Host, Node, ParsedItems}),
    %% FIXME what's the difference between `{drop, ...}` and `{stop, {drop, ...}}`?
    drop;
pubsub_event_handler(Acc) ->
    ?DEBUG("unexpected something on pubsub_event_handler: ~p", [Acc]),
    Acc.

%%--------------------------------------------------------------------

%%| vim: set foldmethod=marker foldmarker=%%|,%%-:
