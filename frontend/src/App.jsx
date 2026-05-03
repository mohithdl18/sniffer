import './index.css'
import { useEffect, useState } from "react";

function App() {
  const [packets, setPackets] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);

  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8000/ws");

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setPackets((prev) => [data, ...prev.slice(0, 500)]);
    };

    return () => socket.close();
  }, []);

  const startCapture = async () => {
    await fetch("http://localhost:8000/start");
  };

  const stopCapture = async () => {
    await fetch("http://localhost:8000/stop");
  };

  const getProtocolColor = (protocol, flag) => {
    if (flag === "RST") return "text-red-500";
    if (protocol === "TCP") return "text-green-400";
    if (protocol === "UDP") return "text-blue-400";
    if (protocol === "ICMP") return "text-yellow-400";
    return "text-gray-400";
  };

  return (
    <div className="bg-gray-900 text-white min-h-screen p-4">
      <h1 className="text-2xl font-bold mb-4">
        Packet Sniffer Dashboard
      </h1>

      <div className="flex gap-4 h-[85vh]">

        {/* LEFT PANEL */}
        <div className="w-2/3 flex flex-col">

          <div className="mb-4 flex gap-4">
            <button
              onClick={startCapture}
              className="bg-green-600 px-4 py-2 rounded"
            >
              Start
            </button>
            <button
              onClick={stopCapture}
              className="bg-red-600 px-4 py-2 rounded"
            >
              Stop
            </button>
          </div>

          <div className="flex-1 overflow-y-auto border border-gray-700 rounded">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-800 sticky top-0">
                  <th className="p-2">Time</th>
                  <th className="p-2">Source</th>
                  <th className="p-2">Destination</th>
                  <th className="p-2">Protocol</th>
                  <th className="p-2">Ports</th>
                  <th className="p-2">Length</th>
                </tr>
              </thead>

              <tbody>
                {packets.map((pkt, i) => (
                  <tr
                    key={i}
                    onClick={() => setSelectedPacket(pkt)}
                    className="text-center border-t border-gray-700 cursor-pointer hover:bg-gray-800"
                  >
                    <td>{pkt.timestamp}</td>
                    <td>{pkt.src}</td>
                    <td>{pkt.dst}</td>

                    <td className={getProtocolColor(pkt.protocol, pkt.flag)}>
                      {pkt.protocol} {pkt.flag && `(${pkt.flag})`}
                    </td>

                    <td>
                      {pkt.sport || "-"} → {pkt.dport || "-"}
                    </td>

                    <td>{pkt.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* RIGHT PANEL */}
        <div className="w-1/3 border border-gray-700 rounded p-4 overflow-auto">
          {!selectedPacket ? (
            <p className="text-gray-400">Click a packet to view details</p>
          ) : (
            <div className="space-y-4 text-sm">

              {/* Layer 1 */}
              <div>
                <h2 className="font-bold text-blue-400">Layer 1 – Ethernet</h2>
                <p>Source MAC: {selectedPacket.src_mac || "-"}</p>
                <p>Destination MAC: {selectedPacket.dst_mac || "-"}</p>
                <p>EtherType: {selectedPacket.ethertype || "-"}</p>
              </div>

              {/* Layer 2 */}
              <div>
                <h2 className="font-bold text-green-400">Layer 2 – IP</h2>
                <p>Source IP: {selectedPacket.src}</p>
                <p>Destination IP: {selectedPacket.dst}</p>
                <p>TTL: {selectedPacket.ttl || "-"}</p>
                <p>Protocol: {selectedPacket.protocol}</p>
                <p>Total Length: {selectedPacket.length}</p>
              </div>

              {/* Layer 3 */}
              <div>
                <h2 className="font-bold text-yellow-400">Layer 3 – Transport</h2>

                {selectedPacket.protocol === "TCP" && (
                  <>
                    <p>Source Port: {selectedPacket.sport}</p>
                    <p>Destination Port: {selectedPacket.dport}</p>
                    <p>Sequence: {selectedPacket.seq || "-"}</p>
                    <p>Ack: {selectedPacket.ack || "-"}</p>
                    <p>Flags: {selectedPacket.flag}</p>
                    <p>Window: {selectedPacket.window || "-"}</p>
                  </>
                )}

                {selectedPacket.protocol === "UDP" && (
                  <>
                    <p>Source Port: {selectedPacket.sport}</p>
                    <p>Destination Port: {selectedPacket.dport}</p>
                    <p>Length: {selectedPacket.length}</p>
                    <p>Checksum: {selectedPacket.checksum || "-"}</p>
                  </>
                )}

                {selectedPacket.protocol === "ICMP" && (
                  <>
                    <p>Type: {selectedPacket.icmp_type || "-"}</p>
                    <p>Code: {selectedPacket.icmp_code || "-"}</p>
                  </>
                )}
              </div>

              {/* Layer 4 */}
              <div>
                <h2 className="font-bold text-purple-400">Layer 4 – Application</h2>
                <p>HTTP Method: {selectedPacket.http_method || "-"}</p>
                <p>URL: {selectedPacket.http_url || "-"}</p>
                <p>DNS Query: {selectedPacket.dns_query || "-"}</p>
              </div>

              {/* Metadata */}
              <div>
                <h2 className="font-bold text-gray-400">Metadata</h2>
                <p>Timestamp: {selectedPacket.timestamp}</p>
                <p>Packet Size: {selectedPacket.length}</p>
                <p>Interface: {selectedPacket.interface || "-"}</p>
              </div>

            </div>
          )}
        </div>

      </div>
    </div>
  );
}

export default App;