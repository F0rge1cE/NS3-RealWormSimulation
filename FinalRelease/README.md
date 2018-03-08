# NS3-RealWormSimulation
### ECE6110@GeorgiaTech
#### Final Project

Collaborators:

* Xueyang Xu 
		
*		xxu343@gatech.edu
* Yunwei Qiang 
* 		yqiang3@gatech.edu
* Nan Li 
* 		nli78@gatech.edu
* Wenxin Fang 
* 		wfang33@gatech.edu
* Xingyu Liu 
* 		xliu488@gatech.edu


**All source code is included in code.zip.**

**Report.pdf is the report of this project.**


To run the program, use commands like following example:

```bash
# If your folder that contains all codes has the name "final".
mpirun -np 1 ./waf --run "final --ScanRate=5 --ScanPattern=Uniform 
							BackbonDelay=10ms --backBoneRate=1Gbps"

```

##Currently Available Parameters
| Name  | Example  | Comment |
|:------------- |:---------------:| -------------:|
| ScanRate      | 5 |        Scan rate of the worm. |
|ScanPattern      | Uniform        |           Scan pattern of the worm. |
| simtime| 1.5        |            Total simulation length, in second. |
| vulnerability| 0.62        |            The probability of a node can be infected. |
| patch | True        |            Enable patching or not. |
|BackboneDelay |10ms        |            Delay of backbone connections. |
| nix | False        |            Enable NIX vector or not. |
|hubInnerRate | 1Mbps        |            Bandwidth of between hub and inner nodes. |
|innerChildRate | 500Kbps        |        Bandwidth of between inner nodes and children. |
| backBoneRate | 1Gbps        |            Bandwidth of between hubs. |
| backGroundTraffic | 50Mbps        |      Adjust the seriousness of background traffic. |

If you wish to use a larger/smaller topology, please modify line 156-158.