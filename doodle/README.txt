# NS3-WormSimulation
### ECE6110@GeorgiaTech
#### Project 3

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



p3a.png is for first required graph. 

p3b.png is for second required graph. 

p3c.png is for third required graph. 


To run the entire program, use commands like following example:

```
mpirun -np 4 ./waf --run "p3 --ScanRate=5 --ScanPattern=Uniform 
							BackbonDelay=10ms --SyncType=Yawns"

// ScanRate in (5, 10, 20)
// ScanPattern in ("Uniform", "Local", "Sequential")
// SyncType in ("Yawns", "Null")
```