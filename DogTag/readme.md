This tool can be used with the Ruckus SmartZone controller in a number of ways. First of all, you need to connect to a SmartZone (SZ) or Virtual SmartZone (vSZ) controller by entering the connection settings at the top and clicking Connect. DogTag will attempt to connect to the SZ/vSZ. When it is successful, the red icon to the right turns green, and DogTag will then read the list of Zones from your SZ/vSZ to populate the drop down box.
You can then export a list of APs in the selected Zone by clicking the 'Export CSV...' button.
Each tab represents an action on the controller.

About
This is just an about screen showing you some brief instructions.

AP Naming and Static Channels
NOTE: The 'Zone' setting is ignored. The AP MAC will be searched throughout the SZ/vSZ
As the name implies, this allows you to import a CSV file (the format is the same as the one you exported above) and push the name, description, location, static channel settings and GPS coordinates to the APs based on the AP MAC address. If the AP MAC is not found on SZ, DogTag will simply skip to the next line. DogTag will NOT create AP entries, the AP must already be in the SZ.

Remove Overrides
NOTE: The 'Zone' setting is ignored. The AP MAC will be searched throughout the SZ/vSZ
This section lets you remove manual AP-specific overrides in SZ/vSZ.
Note that the 'Remove' checkbox means that if it is Checked/Ticked/Enabled, DogTag will REMOVE that setting from the AP.
If you want to KEEP the setting on the AP, then you need to UnCheck/UnTick/Disable this checkbox.
For the AP IP Address, 2G radio and 5G radio options, 'Skip' tells DogTag to leave that setting as is and not change anything on the SZ/vSZ For example, setting the AP IP address to 'Skip' means that those APs which had a static IP will continue to have a static IP, while those which had Dynamic (DHCP) IPs will continue to have Dynamic (DHCP) IPs.

Channels
NOTE: In this case, the 'Zone' setting is used.
This is a simple reporting tool, it does not make any modifications to the SZ/vSZ.
Click 'Refresh' and DogTag will query all APs in the selected Zone for their current WiFi Channel. It will then create a summary of the number of APs using each channel. For reference, it also shows the date/time the data was loaded.
Click 'Refresh' again and DogTag will query all APs once again. This lets you instantly see the channel utilization of all the APs in a Zone. This is especially useful to identify which Auto Channel algorithm to use for a particular Zone (Background Scan vs ChannelFly)

Scaling
NOTE: This section does not rely on a connection to the SZ, therefore it can be used offline.
This is simply a calculator to see how many combined APs + Switches can be managed by a SZ/vSZ cluster. Choose whether you are running vSZ Essentials (/SZ-100) or vSZ High Scale (/SZ-300) mode. Choose which SZ version you intend to run and the number of nodes in the cluster (1-4). As you slide the large slider to the right, you will see the number of APs vs Switches that can be supported in the chosen configuration.
NB: I'm not happy with the look of the Scaling page! Please send me comments on how to improve it... 
