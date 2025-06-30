-module(jamdb_oracle).
-vsn("0.5.12").
-behaviour(gen_server).

%% API
-export([start_link/1, start/1]).
-export([stop/1]).
-export([sql_query/2, sql_query/3]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

-define(default_timeout, 5000).

%% API
-spec start_link(jamdb_oracle_conn:options()) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_list(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

-spec start(jamdb_oracle_conn:options()) -> {ok, pid()} | {error, term()}.
start(Opts) when is_list(Opts) ->
    gen_server:start(?MODULE, Opts, []).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:call(Pid, stop).

sql_query(Pid, Query, Tout) ->
    gen_server:call(Pid, {sql_query, Query, Tout}, Tout).

sql_query(Pid, Query) ->
    gen_server:call(Pid, {sql_query, Query, ?default_timeout}).

%% gen_server callbacks
init(Opts) ->
    case jamdb_oracle_conn:connect(Opts) of
        {ok, State} ->
            {ok, State};
        {ok, Result, _State} ->
            {stop, Result};
        {error, Type, Result, _State} ->
            {stop, {Type, Result}}
    end.

%% Error types: socket, remote, local
handle_call({sql_query, Query, Tout}, _From, State) ->
    try jamdb_oracle_conn:sql_query(State, Query, Tout) of
        {ok, Result, State2} ->
            {reply, {ok, Result}, State2};
        {error, Type, Reason, State2} ->
            {reply, {error, Type, Reason}, State2}
    catch
        error:_Reason ->
            {stop, normal, State}
    end;
handle_call(stop, _From, State) ->
    try jamdb_oracle_conn:disconnect(State, 1) of
        {ok, _Result} ->
            {stop, normal, ok, State}
    catch
        error:_Reason ->
            {stop, normal, State}
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(timeout, State) ->
    {stop, normal, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
