import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Shield, Activity, Terminal, Search } from 'lucide-react';
import TypesenseInstantSearchAdapter from 'typesense-instantsearch-adapter';
import { InstantSearch, SearchBox, Hits } from 'react-instantsearch-hooks-web';

const typesenseInstantsearchAdapter = new TypesenseInstantSearchAdapter({
  server: {
    nodes: [
      {
        host: 'localhost',
        port: '8108',
        protocol: 'http',
      },
    ],
    apiKey: 'xyz',
  },
  additionalSearchParameters: {
    query_by: 'message,service,source_ip',
  },
});

const searchClient = typesenseInstantsearchAdapter.searchClient;

function App() {
  const [stats, setStats] = useState({ total_attacks: 0, by_service: [], top_ips: [] });
  const [liveLog, setLiveLog] = useState(null);

  useEffect(() => {
    // Fetch stats
    const fetchStats = async () => {
      try {
        const res = await axios.get('http://localhost:8000/stats');
        setStats(res.data);
      } catch (err) {
        console.error(err);
      }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 5000);

    // WebSocket for live logs
    const ws = new WebSocket('ws://localhost:8000/ws/live');
    ws.onmessage = (event) => {
      setLiveLog(JSON.parse(event.data));
    };

    return () => {
      clearInterval(interval);
      ws.close();
    };
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono p-8">
      <header className="flex items-center justify-between mb-8 border-b border-green-800 pb-4">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <Shield className="w-8 h-8" /> HONEYPOT DASHBOARD
        </h1>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
          <span>SYSTEM ONLINE</span>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Stats Card */}
        <div className="bg-gray-800 p-6 rounded-lg border border-green-800 shadow-[0_0_10px_rgba(0,255,0,0.1)]">
          <h2 className="text-xl mb-4 flex items-center gap-2"><Activity /> Total Attacks</h2>
          <p className="text-5xl font-bold text-white">{stats.total_attacks}</p>
        </div>

        {/* Top IPs */}
        <div className="bg-gray-800 p-6 rounded-lg border border-green-800 shadow-[0_0_10px_rgba(0,255,0,0.1)]">
          <h2 className="text-xl mb-4 flex items-center gap-2"><Terminal /> Top Attackers</h2>
          <ul>
            {stats.top_ips?.map((ip, i) => (
              <li key={i} className="flex justify-between mb-2">
                <span>{ip.source_ip}</span>
                <span className="text-white font-bold">{ip.count}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Live Feed */}
        <div className="bg-gray-800 p-6 rounded-lg border border-green-800 shadow-[0_0_10px_rgba(0,255,0,0.1)]">
          <h2 className="text-xl mb-4 flex items-center gap-2"><Activity /> Live Feed</h2>
          {liveLog ? (
            <div className="text-sm">
              <p className="text-gray-400">{liveLog.timestamp}</p>
              <p className="font-bold text-white">{liveLog.service}</p>
              <p className="truncate">{liveLog.message}</p>
            </div>
          ) : (
            <p className="text-gray-500">Waiting for activity...</p>
          )}
        </div>
      </div>

      {/* Search Section */}
      <div className="bg-gray-800 p-6 rounded-lg border border-green-800 shadow-[0_0_10px_rgba(0,255,0,0.1)]">
        <h2 className="text-xl mb-4 flex items-center gap-2"><Search /> Log Search</h2>
        <InstantSearch searchClient={searchClient} indexName="logs">
          <div className="mb-4">
            <SearchBox
              classNames={{
                input: 'w-full bg-gray-900 border border-green-700 rounded p-2 text-green-400 focus:outline-none focus:border-green-500',
                submit: 'hidden',
                reset: 'hidden'
              }}
              placeholder="Search logs..."
            />
          </div>
          <Hits hitComponent={({ hit }) => (
            <div className="border-b border-green-900 py-2">
              <span className="text-gray-500 text-xs">{new Date(hit.timestamp * 1000).toLocaleString()}</span>
              <div className="flex gap-4">
                <span className="font-bold w-24">{hit.service}</span>
                <span className="flex-1">{hit.message}</span>
                <span className="text-yellow-500">{hit.source_ip}</span>
              </div>
            </div>
          )} />
        </InstantSearch>
      </div>
    </div>
  );
}

export default App;
