-module(jamdb_oracle).
-vsn("0.5.2").
-behaviour(gen_server).

%% API
-export([start_link/1, start/1]).
-export([stop/1]).
-export([sql_query/2, sql_query/3]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

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

sql_query(Pid, Query, Timeout) ->
    gen_server:call(Pid, {sql_query, Query}, Timeout).

sql_query(Pid, Query) ->
    gen_server:call(Pid, {sql_query, Query}).

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
handle_call({sql_query, Query}, _From, State) ->
    try jamdb_oracle_conn:sql_query(State, Query) of
        {ok, Result, State2} -> 
            {reply, {ok, Result}, State2};
        {error, Type, Reason, State2} ->
            {reply, {error, Type, Reason}, State2}
    catch
        error:Reason ->
            {reply, {error, local, Reason}, State}
    end;
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
