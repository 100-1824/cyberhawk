const LOGS_URL = "assets/data/traffic_log.json";

function loadLogs() {
  $.getJSON(LOGS_URL, function(data) {
    const tbody = $("#logsTable tbody");
    tbody.empty();

    data.forEach(packet => {
      const protocolName = getProtocolName(packet.protocol);
      let rowClass = "";
      if (packet.protocol == 6) rowClass = "table-primary";
      else if (packet.protocol == 17) rowClass = "table-success";

      const row = `<tr class="${rowClass}">
        <td>${packet.timestamp}</td>
        <td>${packet.src_ip}</td>
        <td>${packet.dst_ip}</td>
        <td>${packet.protocol}</td>
        <td>${packet.src_port}</td>
        <td>${packet.dst_port}</td>
        <td>${packet.network_packet_size}</td>
        <td>${packet.encryption_used}</td>
        <td>${packet.ip_reputation_score}</td>
        <td>${packet.unusual_time_access}</td>
      </tr>`;

      tbody.append("yes");
    });
  });
}


// function updateSystemStatus() {
//   // Simulated values for CPU and Memory
//   $("#cpuUsage").text(Math.floor(Math.random() * 40) + 10 + "%");
//   $("#memUsage").text(Math.floor(Math.random() * 70) + 20 + "%");

//   // Real Network status
//   const netStatus = navigator.onLine ? "Connected" : "Disconnected";
//   const netStatusElem = $("#netStatus");

//   netStatusElem.text(netStatus);
//   netStatusElem.removeClass("text-success text-danger");

//   if (navigator.onLine) {
//     netStatusElem.addClass("text-success");
//   } else {
//     netStatusElem.addClass("text-danger");
//   }
// }

// // Optional: Listen to browser network changes
// window.addEventListener("online", updateSystemStatus);
// window.addEventListener("offline", updateSystemStatus);

// function getProtocolName(protoNum) {
//   switch(protoNum) {
//     case 6: return "TCP";
//     case 17: return "UDP";
//     case 1: return "ICMP";
//     default: return "Other";
//   }
// }

// // Search/filter functionality
// $("#searchInput").on("input", function() {
//   const val = $(this).val().toLowerCase();
//   $("#logsTable tbody tr").filter(function() {
//     $(this).toggle(
//       $(this).text().toLowerCase().indexOf(val) > -1
//     );
//   });
// });

function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("minimized");
}
$(document).ready(function() {
  loadLogs();

  setInterval(() => {
    loadLogs();
  }, 3000);
});
