-module(jamdb_oracle).
-behaviour(gen_server).

%% API
-export([start_link/1, start/1]).
-export([stop/1]).
-export([sql_query/2, sql_query/3]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

-include("jamdb_oracle_defaults.hrl").

%% API
-spec start_link(jamdb_oracle_conn:options()) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_list(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

-spec start(jamdb_oracle_conn:options()) -> {ok, pid()} | {error, term()}.
start(Opts) when is_list(Opts) ->
    gen_server:start(?MODULE, Opts, []).

-spec stop(pid()) -> ok.
stop(Pid) ->
    call_infinity(Pid, stop).

sql_query(Pid, Query) ->
    sql_query(Pid, Query, ?DEF_TIMEOUT).

sql_query(Pid, Query, Timeout) ->
    call_infinity(Pid, {sql_query, Query, Timeout}).

%% gen_server callbacks
init(Opts) ->
    {ok, State} = jamdb_oracle_conn:connect(Opts),
    {ok, State}.

%% Error types: socket, remote, local
handle_call({sql_query, Query, Timeout}, _From, State) ->
    try jamdb_oracle_conn:sql_query(State, Query, Timeout) of
        {ok, Result, State2} -> 
            {reply, {ok, Result}, State2};
        {error, socket, Reason, State2} ->
            {ok, State3} = jamdb_oracle_conn:reconnect(State2), %% TODO error
            {reply, {error, socket, Reason}, State3};
        {error, Type, Reason, State2} ->
            {reply, {error, Type, Reason}, State2}
    catch
        _Class:Reason ->
            Stacktrace = erlang:get_stacktrace(),
            ErrDesc = [
                {reason, Reason},
                {stacktrace, Stacktrace}
            ],
            {ok, State2} = jamdb_oracle_conn:reconnect(State),
            {reply, {error, local, {unknown_error, ErrDesc}}, State2}
    end;
%handle_call({prepare, Query}, _From, State) ->
%handle_call({execute, Query}, _From, State) ->
handle_call(stop, _From, State) ->
    {ok, _InitOpts} = jamdb_oracle_conn:disconnect(State),
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% internal
call_infinity(Pid, Msg) ->
    gen_server:call(Pid, Msg, infinity).
