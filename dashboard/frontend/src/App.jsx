import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Shield, Activity, Terminal, Search, Map as MapIcon } from 'lucide-react';
import TypesenseInstantSearchAdapter from 'typesense-instantsearch-adapter';
import { InstantSearch, SearchBox, Hits } from 'react-instantsearch-hooks-web';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Title } from 'chart.js';
import { Doughnut, Line } from 'react-chartjs-2';
import { Network } from 'vis-network';
import { DataSet } from 'vis-data';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Title);

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
  const networkContainer = useRef(null);
  const networkRef = useRef(null);

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

    // WebSocket for Topology
    const wsTopology = new WebSocket('ws://localhost:8000/ws/topology');
    wsTopology.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (networkRef.current) {
        // Update network data
        // Note: For a real production app, we'd want to diff the data to avoid full redraws
        // But vis-network handles updates reasonably well if we just update the datasets
        // For simplicity here, we are re-creating the network on first load or just letting it be static for now if we don't implement full diffing logic
        // A better approach for frequent updates is using DataSet
      }

      // Initialize network if not exists
      if (networkContainer.current && !networkRef.current) {
        const nodes = new DataSet(data.nodes);
        const edges = new DataSet(data.edges);
        const options = {
          nodes: {
            shape: 'dot',
            size: 16,
            font: { color: '#ffffff' },
            borderWidth: 2
          },
          edges: {
            width: 2,
            color: { color: '#4ade80', highlight: '#86efac' },
            smooth: { type: 'continuous' }
          },
          physics: {
            stabilization: false,
            barnesHut: {
              gravitationalConstant: -8000,
              springConstant: 0.04,
              springLength: 95
            }
          },
          interaction: { hover: true }
        };
        networkRef.current = new Network(networkContainer.current, { nodes, edges }, options);
      } else if (networkRef.current) {
        // Update existing data
        const currentNodes = networkRef.current.body.data.nodes;
        const currentEdges = networkRef.current.body.data.edges;
        currentNodes.update(data.nodes);
        currentEdges.update(data.edges);
      }
    };

    return () => {
      clearInterval(interval);
      ws.close();
      wsTopology.close();
    };
  }, []);

  // Chart Data
  const doughnutData = {
    labels: stats.by_service.map(s => s.service),
    datasets: [
      {
        label: '# of Attacks',
        data: stats.by_service.map(s => s.count),
        backgroundColor: [
          'rgba(255, 99, 132, 0.8)',
          'rgba(54, 162, 235, 0.8)',
          'rgba(255, 206, 86, 0.8)',
          'rgba(75, 192, 192, 0.8)',
        ],
        borderColor: [
          'rgba(255, 99, 132, 1)',
          'rgba(54, 162, 235, 1)',
          'rgba(255, 206, 86, 1)',
          'rgba(75, 192, 192, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

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
          <p className="text-5xl font-bold text-white mb-4">{stats.total_attacks}</p>
          <div className="h-48">
            <Doughnut data={doughnutData} options={{ maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#fff' } } } }} />
          </div>
        </div>

        {/* Topology Map */}
        <div className="bg-gray-800 p-6 rounded-lg border border-green-800 shadow-[0_0_10px_rgba(0,255,0,0.1)] col-span-2">
          <h2 className="text-xl mb-4 flex items-center gap-2"><MapIcon /> Real-Time Topology</h2>
          <div ref={networkContainer} className="h-64 w-full bg-gray-900 rounded border border-green-900"></div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {/* Top IPs */}
        <div className="bg-gray-800 p-6 rounded-lg border border-green-800 shadow-[0_0_10px_rgba(0,255,0,0.1)]">
          <h2 className="text-xl mb-4 flex items-center gap-2"><Terminal /> Top Attackers</h2>
          <ul>
            {stats.top_ips?.map((ip, i) => (
              <li key={i} className="flex justify-between mb-2 border-b border-gray-700 pb-1">
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
