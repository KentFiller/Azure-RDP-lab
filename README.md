<h1>Failed RDP to IP Geolocation Information</h1>

<h2>Description</h2>
<b>This repository contains a PowerShell script designed to parse Windows Event Log information for failed RDP attacks. The script utilizes a third-party API to gather geographic information about the attackers' location.
</b>
<br />
<br />
This script is deployed in Microsoft's Azure environment and is integrated with Azure Sentinel for Security Information and Event Management (SIEM). In order to attract global attacks, a live virtual machine is purposefully left open to the internet with its firewall disabled to act as a honeypot. The custom PowerShell script determines the attackers geolocation and logs the information in a specific format. To extract the data for visualization, we use a Query placed in the Log Analytics Workspace Logs Query to plot the data in the world map.
<br />
<br />

<p align="center">
<img src="https://iili.io/J7MlQII.png" height="85%" width="85%" alt="Geolocator API website"/>
</p>
<h2>Languages Used</h2>

- <b>PowerShell:</b> Extract RDP failed login logs from Windows Event Viewer
- <b>Kusto Query Language (KQL):</b> Extract Data from RDP custom logs for viewing in a world map

<h2>Utilities Used</h2>

- <b>ipgeolocation.io:</b> IP Address to Geolocation API

<h2>Identification of failed login attempts; Custom logs with geodata</h2>

<p align="center">
<img src="https://iili.io/J7Me3SS.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>

<h2>Sentinel Workbook with extracted data from the query being plotted in the world map</h2>

<p align="center">
<img src="https://iili.io/J7MwxPp.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>

<h3>Full Kusto Query Language (KQL) Script used</h3>

```kql
FAILED_RDP_WITH_GEO_CL
| extend latitude = todouble(extract('latitude:([^,]+)', 1, RawData)),
         longitude = todouble(extract('longitude:([^,]+)', 1, RawData)),
         destinationhost = tostring(extract('destinationhost:([^,]+)', 1, RawData)),
         username = tostring(extract('username:([^,]+)', 1, RawData)),
         sourcehost = tostring(extract('sourcehost:([^,]+)', 1, RawData)),
         state = tostring(extract('state:([^,]+)', 1, RawData)),
         country = tostring(extract('country:([^,]+)', 1, RawData)),
         label = tostring(extract('label:([^,]+)', 1, RawData)),
         timestamp = todatetime(extract('timestamp:([^,]+)', 1, RawData))
| where destinationhost != "samplehost" and RawData != ""
| summarize event_count = count() by sourcehost, latitude, longitude, country, label, destinationhost
```
This KQL script extracts relevant information from the custom logs and transforms it into a structured format for analysis. Key elements such as latitude, longitude, country, and sourcehost are identified and used to summarize the count of failed login events. This data is essential for creating visualizations in the Azure Sentinel Workbook.
Sentinel Workbook visualizes unsuccessful RDP login attempts on a world map to provide a global overview. Plotting each point to represent a different attack simplifies analysis and pattern recognition.

<h2>Azure Sentinel Overview data spanning 7 days</h2>
<p align="center">
<img src="https://iili.io/J7MlZXt.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>
<h2>World map visualization of Azure Sentinel data over approximately 24 hours</h2>
<p align="center">
<img src="https://iili.io/J7MlP7R.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>
<h2>Analysis after a continuous 7-8 day exposure to the public internet</h2>
<p align="center">
<img src="https://iili.io/J7Mliep.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
