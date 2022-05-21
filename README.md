# Writeup Lets Defend SOC 145 - Ransomware Detected

Writeup simple let's defend SOC 145 Ransomware Detected. Monitoring, Log Management, Case Management, Endpoint Security.
## Source link

https://app.letsdefend.io/
## Third party tools
- Any run : https://app.any.run/
- Virus Total :https://www.virustotal.com/gui/home/search
- Malwaoverview with Trigae : https://github.com/alexandreborges/malwoverview
- HybridAnalysis : https://www.hybrid-analysis.com/


## Details Alert 
On May 23, 2021, at 7.32 Pm, the SOC lets Defend team found an alert that appears on the Monitoring menu. The result of the event description contains a notification of an attempt to spread ransomware on a client environment. The event was detected with id 92 and source ip 172.16.17.88. It is known that the user is the master "MarkPRD". According to the information we got, the file indicated as ransomware is ab.exe with the hash value shown in the image below. Don't forget, the reason we focus on analyzing the event is the "high" severity value.

![image](https://user-images.githubusercontent.com/43168046/169574634-88951164-9284-4b44-a5eb-866b4ddbcd6c.png)


## The First Stage

After knowing the details of the event, we enter into the analysis process. Starting with the stage of gathering detailed information.

![image](https://user-images.githubusercontent.com/43168046/169574880-cff29123-30c3-445b-bf32-0b9fa13ebf63.png)

We started collecting information through "Log Management" and "Endpoint Security". More detailed information about "Log Management" & "Endpoint Security" can be read at the following link
- https://www.humio.com/glossary/log-management/
- https://www.trellix.com/en-us/security-awareness/endpoint/what-is-endpoint-security.html#:~:text=Endpoint%20security%20is%20the%20practice,the%20cloud%20from%20cybersecurity%20threats..

### Log Management Result

Click the "Log Management" menu, we search by keyword source ip 172.16.17.88. The search results show 2 communication traffic on that ip. where the destination ip consists of 81.169.145.105 & 192.64.119.190. This indicates that the host can still communicate with other users.
![image](https://user-images.githubusercontent.com/43168046/169577229-6e2654dc-7e3a-4210-9c5c-d7a032038385.png)

### Endpoint Security Result

Continuing the process of gathering information, we enter the "Endpoint Security" menu. The SOC team uses the same keyword, namely 172.16.17.88. Through the "Endpoint Security" menu, we get detailed information such as Hostname, IP Address, OS version, Client/Server and Device Status. Based on the results of the check, we conclude that the malware is *not Quarantined* .

![image](https://user-images.githubusercontent.com/43168046/169579671-bbee3c36-e8e0-4602-9dbc-d2b218f65b09.png)

## The Second Stage

Through the information that was obtained, the SOC Team concluded that the device indicated by the malware was not in quarantine. so we have to do the analysis immediately so as not to cause problems.

![image](https://user-images.githubusercontent.com/43168046/169581092-2196e2e0-8b7e-4a9e-9a58-b0d113121592.png)

### Analysis with ANYRUN
anyrun is one of the many third-party SOC tools that are useful in helping analyze malware. The concept of these tools is a sandbox, so the analysis is based on dynamic analysis.
![image](https://user-images.githubusercontent.com/43168046/169577229-6e2654dc-7e3a-4210-9c5c-d7a032038385.png)

when we tried to run the ab.bin file which we successfully downloaded. We get information as shown in the image below:


![image](https://user-images.githubusercontent.com/43168046/169650695-d7beec92-1b8d-4639-a873-7dbef5d3d136.png)
![image](https://user-images.githubusercontent.com/43168046/169650716-261a8051-9575-466c-a4f3-2f907cd95476.png)
![image](https://user-images.githubusercontent.com/43168046/169650723-a2f2cb54-9866-410b-bd4f-19cb627353c8.png)

The ab.bin file will run the process behind the scenes. Through the anyrun dashboard, we found as many as 247 file modifications. After we check in more detail. There are lots of delete system backup commands.

### Analysis with Virus Totals
VirusTotal is an Alphabet product that analyzes file, URL, domain and IP address searches to detect malware and other types of threats, and automatically shares them with the security community.

To view the VirusTotal report, you need to send the attached file, IP address, or domain to VirusTotal. 

we try to do a report search on the online data. this search is based on the hash value we already know.

![image](https://user-images.githubusercontent.com/43168046/169657968-23c22722-7dc3-4494-8f02-4ffe6b8fadaa.png)

it can be seen that in the total virus, the hash is indicated to have a bad reputation. of 59/69. other than that the data we got was updated since 5 days ago.  

the information we get from virus totals is almost the same as anyrun. where the ab.bin file runs the delete process behind the scenes

![image](https://user-images.githubusercontent.com/43168046/169658200-f1a3803a-b2b2-4498-b702-265fbad7529c.png)

### Analysis with Malwoverview
Malwoverview is a first response tool used for threat hunting and offers intel information from Virus Total, Hybrid Analysis, URLHaus, Polyswarm, Malshare, Alien Vault, Malpedia, ThreatCrowd, Malware Bazaar, ThreatFox, Triage and it is able to scan Android devices against VT.

using malwoverview, we tried to find more detailed information about the ab.bin file. we use api from triage. information comes from triage, there are several reports that can be seen in the picture.
![image](https://user-images.githubusercontent.com/43168046/169661766-8144c9ee-4088-4775-a953-49d14077c091.png)

The ab.bin.zip file is indicated as avaddon malware. where the malware belongs to the ransomware family. This is evidenced by a valid signature.

![image](https://user-images.githubusercontent.com/43168046/169661776-27c17879-0946-4d87-be1e-5449acdd0982.png)


### Analysis with Hybrid Analysis
Hybrid analyst is a sandbox malware tool just like anyrun.

To strengthen the results of our analysis, that the ab.bin file is malware. once again we tried to dynamically analyze the file using another sandbox malware platform.
![image](https://user-images.githubusercontent.com/43168046/169661908-7e32a012-4863-43e5-aa50-961c314dcde0.png)

![image](https://user-images.githubusercontent.com/43168046/169661920-f9ba78df-6125-441b-a2ca-0c729c14bee2.png)

![image](https://user-images.githubusercontent.com/43168046/169661935-5c8b1a8a-60a6-45ab-b8d1-147e4e4e11a8.png)

the results we get through the hybrid analysis tools really strengthen the analysis. where we the information consists of:
1. Antivurus detects above 76% that the ab.bin file is malware
2. The ab.bin file is indicated as ransomware
3. This file has been tested on os version 32 and 64 bit
4. Incident response generated by the file is also very dangerous.

and don't forget we also found important notes left by the attacker, namely the website that must be visited avaddonbotrxmuyl.onion

![image](https://user-images.githubusercontent.com/43168046/169662231-1cc30bb6-62b5-4912-8b83-a5e0c4f2324a.png)



## Running Tests

To run tests, run the following command

```bash
  npm run test
```


## Used By

This project is used by the following companies:

- Company 1
- Company 2


## Acknowledgements

 - [Awesome Readme Templates](https://awesomeopensource.com/project/elangosundar/awesome-README-templates)
 - [Awesome README](https://github.com/matiassingers/awesome-readme)
 - [How to write a Good readme](https://bulldogjob.com/news/449-how-to-write-a-good-readme-for-your-github-project)

