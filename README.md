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

