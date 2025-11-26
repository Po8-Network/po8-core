import { useEffect, useState } from 'react'

const RPC_URL = 'http://localhost:8833/rpc';

interface MiningStats {
  blocks_mined: number;
  total_earnings: number;
  hash_rate: number;
  miner_address: string;
  is_mining: boolean;
}

interface NetworkStats {
  network_hashrate: string;
  difficulty: string;
  peer_count: number;
}

interface Block {
    height: number;
    timestamp: number;
    nonce: number;
    signature: number[];
    prev_hash: number[];
    proof: number[];
    difficulty?: number;
    txs?: any[];
}

function App() {
  const [blockHeight, setBlockHeight] = useState(0);
  const [stats, setStats] = useState<MiningStats | null>(null);
  const [networkInfo, setNetworkInfo] = useState<NetworkStats | null>(null);
  const [networkId, setNetworkId] = useState<number | null>(null);
  const [recentBlocks, setRecentBlocks] = useState<Block[]>([]);
  const [isToggling, setIsToggling] = useState(false);
  const [selectedBlock, setSelectedBlock] = useState<Block | null>(null);

  const fetchData = async () => {
    try {
      const heightRes = await rpcCall('get_block_count', []);
      if (heightRes.result) setBlockHeight(heightRes.result);

      const netRes = await rpcCall('net_version', []);
      if (netRes.result) setNetworkId(netRes.result);

      const mineRes = await rpcCall('get_mining_stats', []);
      if (mineRes.result) setStats(mineRes.result);

      const infoRes = await rpcCall('get_network_info', []);
      if (infoRes.result) setNetworkInfo(infoRes.result);

      const blocksRes = await rpcCall('get_recent_blocks', []);
      if (blocksRes.result) setRecentBlocks(blocksRes.result);

    } catch (e) {
      console.error(e);
    }
  };

  const rpcCall = async (method: string, params: any[]) => {
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method, params, id: 1 })
    });
    return await res.json();
  };

  const toggleMining = async () => {
    if (!stats || isToggling) return;
    setIsToggling(true);
    const method = stats.is_mining ? 'stop_mining' : 'start_mining';
    try {
        await rpcCall(method, []);
        await fetchData();
    } catch (e) {
        console.error(e);
    }
    setIsToggling(false);
  }

  const openBlock = async (height: number) => {
      try {
        const res = await rpcCall('get_block_by_height', [height]);
        if (res.result) setSelectedBlock(res.result);
      } catch (e) {
          console.error(e);
      }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 1000);
    return () => clearInterval(interval);
  }, []);

  const getNetworkName = (id: number | null) => {
    if (!id) return 'Connecting...';
    if (id === 1337) return 'Development';
    if (id === 80001) return 'Testnet';
    if (id === 8) return 'Mainnet';
    return `Chain ${id}`;
  }

  const toHex = (arr: number[]) => {
      if (!arr) return '';
      return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  return (
    <div style={{ padding: '40px', maxWidth: '1000px', margin: '0 auto', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '24px', color: '#38bdf8' }}>Po8 Node Dashboard</h1>
          <div style={{ fontSize: '14px', color: '#94a3b8', marginTop: '4px' }}>Local Miner Interface</div>
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
           {stats && (
            <button 
                onClick={toggleMining}
                disabled={isToggling}
                style={{
                    background: stats.is_mining ? '#ef4444' : '#22c55e',
                    color: 'white',
                    border: 'none',
                    padding: '8px 16px',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    fontWeight: 600,
                    marginRight: '12px'
                }}
            >
                {stats.is_mining ? 'Stop Mining' : 'Start Mining'}
            </button>
           )}
          <Badge>{getNetworkName(networkId)}</Badge>
          <Badge color="#22c55e">Running</Badge>
        </div>
      </header>

      {stats && stats.miner_address && (
          <div style={{ background: '#1e293b', padding: '16px', borderRadius: '8px', marginBottom: '24px', borderLeft: '4px solid #38bdf8', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                  <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
                      Rewards Deposited To
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: '14px', color: '#f8fafc', wordBreak: 'break-all' }}>
                      {stats.miner_address}
                  </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
                      Mining Status
                  </div>
                  <div style={{ color: stats.is_mining ? '#22c55e' : '#f59e0b', fontWeight: 600 }}>
                      {stats.is_mining ? 'ACTIVE (NPU)' : 'PAUSED'}
                  </div>
              </div>
          </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '30px' }}>
        <Card title="Current Height" value={blockHeight.toLocaleString()} />
        <Card title="Real Hashrate" value={stats ? stats.hash_rate.toLocaleString() : '0'} unit="H/s" />
        <Card title="Blocks Mined" value={stats ? stats.blocks_mined.toLocaleString() : '0'} />
        <Card 
            title="Total Earnings" 
            value={stats ? stats.total_earnings.toLocaleString() : '0'} 
            unit="PO8" 
            highlight 
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '30px' }}>
          <div>
            <h2 style={{ fontSize: '18px', color: '#e2e8f0', marginBottom: '20px' }}>Recent Blocks</h2>
            <div style={{ background: '#1e293b', borderRadius: '12px', overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', color: '#cbd5e1', fontSize: '14px' }}>
                    <thead>
                        <tr style={{ borderBottom: '1px solid #334155', background: '#0f172a' }}>
                            <th style={{ padding: '12px', textAlign: 'left' }}>Height</th>
                            <th style={{ padding: '12px', textAlign: 'left' }}>Time</th>
                            <th style={{ padding: '12px', textAlign: 'left' }}>Nonce</th>
                            <th style={{ padding: '12px', textAlign: 'right' }}>Sig Size</th>
                        </tr>
                    </thead>
                    <tbody>
                        {recentBlocks.map(b => (
                            <tr 
                                key={b.height} 
                                onClick={() => openBlock(b.height)}
                                style={{ borderBottom: '1px solid #334155', cursor: 'pointer', transition: 'background 0.2s' }}
                                onMouseOver={(e) => e.currentTarget.style.background = '#334155'}
                                onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}
                            >
                                <td style={{ padding: '12px', color: '#38bdf8', fontWeight: 600 }}>#{b.height}</td>
                                <td style={{ padding: '12px' }}>{new Date(b.timestamp * 1000).toLocaleTimeString()}</td>
                                <td style={{ padding: '12px', fontFamily: 'monospace' }}>{b.nonce}</td>
                                <td style={{ padding: '12px', textAlign: 'right' }}>{b.signature ? b.signature.length : 0} B</td>
                            </tr>
                        ))}
                         {recentBlocks.length === 0 && (
                            <tr><td colSpan={4} style={{ padding: '20px', textAlign: 'center', color: '#64748b' }}>No blocks yet</td></tr>
                        )}
                    </tbody>
                </table>
            </div>
          </div>

          <div>
            <h2 style={{ fontSize: '18px', color: '#e2e8f0', marginBottom: '20px' }}>Network Status</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <StatBox label="Net Hashrate" value={networkInfo?.network_hashrate || '-'} />
                <StatBox label="Difficulty" value={networkInfo?.difficulty || '-'} />
                <StatBox label="Peers" value={networkInfo?.peer_count?.toString() || '-'} />
                <StatBox label="Consensus" value="BFT + PoUW" />
                <StatBox label="EVM Status" value="Active" />
            </div>

            <h2 style={{ fontSize: '18px', color: '#e2e8f0', marginBottom: '20px', marginTop: '30px' }}>Logs</h2>
             <div style={{ padding: '16px', background: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', fontFamily: 'monospace', fontSize: '11px', color: '#64748b', height: '150px', overflowY: 'auto' }}>
                <div style={{ color: '#22c55e' }}>[INFO] Node Active</div>
                <div style={{ color: '#38bdf8' }}>[P2P] Listening on :8834 (Mixnet Framed)</div>
                <div style={{ color: '#a855f7' }}>[EVM] Initialized in-memory state</div>
                {stats?.is_mining ? <div style={{ color: '#eab308' }}>[MINER] Mining on M1 NPU...</div> : <div style={{ color: '#64748b' }}>[MINER] Idle</div>}
                {recentBlocks.length > 0 && <div style={{ color: '#22c55e' }}>[CONSENSUS] Block #{recentBlocks[0].height} committed</div>}
            </div>
          </div>
      </div>

      {selectedBlock && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={() => setSelectedBlock(null)}>
            <div style={{ background: '#1e293b', padding: '30px', borderRadius: '12px', width: '600px', maxHeight: '80vh', overflowY: 'auto' }} onClick={e => e.stopPropagation()}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
                    <h2 style={{ margin: 0, color: '#38bdf8' }}>Block #{selectedBlock.height}</h2>
                    <button onClick={() => setSelectedBlock(null)} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '24px' }}>&times;</button>
                </div>
                <div style={{ display: 'grid', gap: '12px', color: '#e2e8f0', fontSize: '14px' }}>
                    <div style={{display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #334155', paddingBottom: '8px'}}>
                        <span style={{color: '#94a3b8'}}>Timestamp</span>
                        <span>{new Date(selectedBlock.timestamp * 1000).toLocaleString()}</span>
                    </div>
                    <div style={{display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #334155', paddingBottom: '8px'}}>
                        <span style={{color: '#94a3b8'}}>Nonce</span>
                        <span style={{fontFamily: 'monospace'}}>{selectedBlock.nonce}</span>
                    </div>
                    <div style={{display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #334155', paddingBottom: '8px'}}>
                        <span style={{color: '#94a3b8'}}>Difficulty</span>
                        <span>{selectedBlock.difficulty || 8} (Leading Zeros)</span>
                    </div>
                    
                    <div style={{marginTop: '12px'}}>
                        <div style={{color: '#94a3b8', fontSize: '12px', marginBottom: '4px'}}>Previous Hash</div>
                        <div style={{fontFamily: 'monospace', background: '#0f172a', padding: '8px', borderRadius: '4px', wordBreak: 'break-all', fontSize: '12px'}}>
                            {toHex(selectedBlock.prev_hash)}
                        </div>
                    </div>

                    <div style={{marginTop: '12px'}}>
                        <div style={{color: '#94a3b8', fontSize: '12px', marginBottom: '4px'}}>Proof Hash (PoUW)</div>
                        <div style={{fontFamily: 'monospace', background: '#0f172a', padding: '8px', borderRadius: '4px', wordBreak: 'break-all', fontSize: '12px'}}>
                            {toHex(selectedBlock.proof)}
                        </div>
                    </div>

                    <div style={{marginTop: '12px'}}>
                        <div style={{color: '#94a3b8', fontSize: '12px', marginBottom: '4px'}}>ML-DSA-65 Signature</div>
                        <div style={{fontFamily: 'monospace', background: '#0f172a', padding: '8px', borderRadius: '4px', wordBreak: 'break-all', fontSize: '12px', maxHeight: '60px', overflowY: 'auto'}}>
                            {toHex(selectedBlock.signature)}
                        </div>
                    </div>
                    
                    <h3 style={{ marginTop: '20px', marginBottom: '10px', fontSize: '16px', color: '#94a3b8' }}>Transactions ({selectedBlock.txs?.length || 0})</h3>
                    <div style={{ background: '#0f172a', padding: '10px', borderRadius: '6px', fontFamily: 'monospace' }}>
                        {selectedBlock.txs?.length ? selectedBlock.txs.map((tx: any, i: number) => (
                            <div key={i}>{tx}</div>
                        )) : <div style={{ color: '#64748b' }}>No transactions</div>}
                    </div>
                </div>
            </div>
        </div>
      )}
    </div>
  )
}

const Card = ({ title, value, unit, highlight }: any) => (
  <div style={{ background: '#1e293b', padding: '24px', borderRadius: '12px', border: highlight ? '1px solid #38bdf8' : 'none' }}>
    <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
      {title}
    </div>
    <div style={{ fontSize: '32px', fontWeight: 700, color: highlight ? '#38bdf8' : 'white' }}>
      {value} <span style={{ fontSize: '16px', color: '#64748b', fontWeight: 500 }}>{unit}</span>
    </div>
  </div>
);

const StatBox = ({ label, value }: any) => (
  <div style={{ background: '#1e293b', padding: '16px', borderRadius: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
    <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {label}
    </div>
    <div style={{ fontSize: '16px', fontWeight: 600, color: '#e2e8f0' }}>
      {value}
    </div>
  </div>
);

const Badge = ({ children, color = '#334155' }: any) => (
  <div style={{ background: color, padding: '6px 12px', borderRadius: '20px', fontSize: '12px', fontWeight: 600, color: 'white' }}>
    {children}
  </div>
);

export default App
