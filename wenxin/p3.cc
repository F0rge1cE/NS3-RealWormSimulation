/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
author :
  Wenxin Fang
  Xingyu Liu
  Nan Li
  Xueyang XU
  Yunwei Qiang
*/
#include <iostream>
#include <stdio.h>
#include <string>
#include <sys/time.h>
#include <math.h>  
//#include <vector>
#include <time.h>
#include <iomanip>
#include <assert.h>

//#include "ns3/random-variable-stream.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/netanim-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/stats-module.h"
#include "ns3/random-variable-stream.h"

#include "ns3-worm.h"

#include "p2pCampusHelper.h"
// ****** For MPI
#include "ns3/mpi-interface.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4-nix-vector-helper.h"
#include "ns3/ipv4-address-helper.h"
#ifdef NS3_MPI
#include <mpi.h>
#endif

// ------------ Define worm types    ---------------
// #define TCPWORMTYPE  1
#define UDPWORMTYPE  2
#define WORMTYPE     UDPWORMTYPE
#define VULNERABILITY  1
#define SCANRATE       5
#define SCANRANGE      0
#define PAYLOAD        404
#define SIMTIME        3.0
#define PATCH false
#define SEEDVALUE      1
#define NIX true
#define NULLMSG false
#define TRACING false
#define PATTERNID 3

using namespace ns3;
using namespace std;

typedef struct timeval TIMER_TYPE;
#define TIMER_NOW(_t) gettimeofday (&_t,NULL);
#define TIMER_SECONDS(_t) ((double)(_t).tv_sec + (_t).tv_usec * 1e-6)
#define TIMER_DIFF(_t1, _t2) (TIMER_SECONDS (_t1) - TIMER_SECONDS (_t2))

int main(int argc, char* argv[])
{
#ifdef NS3_MPI
  TIMER_TYPE t0, t1, t2;
  TIMER_NOW (t0);


  GlobalValue::Bind ("SimulatorImplementationType",
  StringValue ("ns3::DistributedSimulatorImpl"));
  uint32_t scanrate = SCANRATE;
  uint32_t patternId = PATTERNID;
  uint32_t payload = PAYLOAD;
  uint32_t seedValue = SEEDVALUE;
  double vulnerability = VULNERABILITY;
  double simtime = SIMTIME;
  bool logTop = 0;
  string backBoneDelay ("10ms");
  string scanPattern ("Uniform");
  string nullmsg ("Yawns");
  bool nix = NIX;
  bool tracing = TRACING;
  bool patch = PATCH;

  CommandLine cmd;
  cmd.AddValue ("ScanRate",      "Scan rate",                    scanrate);
  cmd.AddValue ("ScanPattern",      "Scan pattern",                    scanPattern);
  cmd.AddValue ("patternId",      "Pattern Id",                  patternId);
  cmd.AddValue ("payload",       "Payload",                      payload);
  cmd.AddValue ("seedvalue",     "Seed value for RNG",           seedValue);
  cmd.AddValue ("vulnerability", "Vulnerability to infection",   vulnerability);
  cmd.AddValue ("simtime",       "Simulator time in seconds",    simtime);
  cmd.AddValue ("patch",       "Enable Universal Patching",    patch);
  cmd.AddValue ("logTop",        "Display the topology stats",   logTop);
  cmd.AddValue ("BackboneDelay",        "change back bone Delay",   backBoneDelay);

  // ****** For MPI
  cmd.AddValue ("nix", "Enable the use of nix-vector or global routing", nix);
  cmd.AddValue ("SyncType", "Enable the use of null-message synchronization", nullmsg);
  cmd.AddValue ("tracing", "Enable pcap tracing", tracing);
  // ******

  cmd.Parse (argc,argv);

  //payload = scanrate * 100;
  if(scanPattern=="Uniform"){
    patternId = 0;
  }else if(scanPattern == "Local"){
    patternId = 1;
  }else if(scanPattern == "Sequential"){
    patternId = 2;
  }

  if(nullmsg=="Null"){
    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::NullMessageSimulatorImpl"));
  }else{
      GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::DistributedSimulatorImpl"));
  }
  
  SeedManager::SetSeed (seedValue);
  Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable> ();

  // Enable parallel simulator with the command line arguments
  MpiInterface::Enable (&argc, &argv);

  // Get rank and total number of CPUs.
  uint32_t systemId = MpiInterface::GetSystemId ();
  uint32_t systemCount = MpiInterface::GetSize ();

  // We only do simulation with 4 processors.
  if (systemCount != 1 && systemCount != 2 && systemCount != 4){
      std::cout << "Only 1, 2 or 4 processors are accepted. Now have " << systemCount << std::endl;
      return 1;
  }

  uint32_t nInner = 8;
  uint32_t nChild = 16;
  uint32_t nHub = 4;

  PointToPointHelper hubInner;
  hubInner.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
  hubInner.SetChannelAttribute("Delay", StringValue("5ms"));

  PointToPointHelper innerChild;
  innerChild.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
  innerChild.SetChannelAttribute("Delay", StringValue("8ms"));

  // ****** For MPI
  // P2P between hubs

  PointToPointHelper hub2hub;
  hub2hub.SetDeviceAttribute("DataRate", StringValue("50Mbps"));
  hub2hub.SetChannelAttribute("Delay", StringValue(backBoneDelay));

  // Create nodes

  std::vector<PointToPointCampusHelper> bombs;
  for(uint32_t i = 0; i<nHub; i++){
    PointToPointCampusHelper bomb(nInner, hubInner, nChild, innerChild, 0);
    bombs.push_back(bomb);
  }

  // NetDeviceContainer hubDevice;
  std::vector<NetDeviceContainer> hub2HubDevs;
  for(uint32_t i = 0; i<nHub-1; i++){
    NetDeviceContainer hub2hub_dev = hub2hub.Install (bombs[i].GetHub(), bombs[i+1].GetHub());
    hub2HubDevs.push_back(hub2hub_dev);
  }

  InternetStackHelper stack;
  
  // Apply Nix Vector
  if (nix){
      std::cout << "Nix Vector Enabled " << std::endl;
      Ipv4NixVectorHelper nixRouting;
      stack.SetRoutingHelper (nixRouting); // has effect on the next Install ()
  }
  stack.InstallAll ();

  ostringstream oss;
  
  Ipv4AddressHelper address;
  for(uint32_t i = 0; i<bombs.size(); i++){
    oss.str ("");
    oss << "10." << i+1 << ".1.0";
    address.SetBase(oss.str().c_str (), "255.255.255.0");
    bombs[i].AssignIpv4Addresses(address);
  }

  for(uint32_t i = 0; i<hub2HubDevs.size(); i++){
    oss.str ("");
    oss << "10." << i + bombs.size() + 1 << ".1.0";
    address.SetBase(oss.str().c_str (), "255.255.255.0");
    address.Assign(hub2HubDevs[i]);
  }

  Worm::SetPacketSize(payload);
  uint32_t numVulnerableNodes = 0;

  for (uint32_t i = 0; i<bombs.size(); i++){
    for(uint32_t j = 0; j < nChild * nInner; j++){
      PacketSinkHelper sinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9999));
      ApplicationContainer sinkApp = sinkHelper.Install (bombs[i].GetChildNode(j));
      sinkApp.Start(Seconds (0.0));

      OnOffHelper client ("ns3::UdpSocketFactory", Address ());
      AddressValue remoteAddress (InetSocketAddress (bombs[(i+1)%bombs.size()].GetChildIpv4Address(j), 9999));
      client.SetAttribute ("Remote", remoteAddress);
      client.SetAttribute ("MaxBytes", UintegerValue(0));
      client.SetAttribute ("DataRate",StringValue ("1Kbps"));
      client.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
      client.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));

      ApplicationContainer clientApp;
      clientApp.Add (client.Install (bombs[i].GetChildNode(j)));
      clientApp.Start (Seconds (0.0));
    }
  }
  

  //Add the worm application to each node.
  if(systemId == 0%systemCount){
    for(uint32_t i=0; i < nChild * nInner; i++)
    {
      Ptr<Worm> wormApp = CreateObject<Worm> ();

      if (uv->GetValue(0.0, 1.0) <= vulnerability) {
        wormApp->SetVulnerable (true);
        if(i!=0) numVulnerableNodes++;
      }

      std::string temp1 = "a" + std::to_string(i) + " " + std::to_string(systemId);
      wormApp->SetName(temp1);
      wormApp->SetSysId(systemId);

      // Set the initial infected node.
      if(i == 0){
        wormApp->SetVulnerable (true);
        wormApp -> SetInfected (true);
        wormApp -> SetTotalNumOfInfected(1);
        numVulnerableNodes++;
      }
      wormApp->SetPatching (patch);
      wormApp->SetPatchingTime (sqrt(uv->GetValue(SIMTIME / 20, SIMTIME * 1.5) * SIMTIME * 1.5));


      wormApp->SetStartTime (Seconds (0.0));
      wormApp->SetStopTime (Seconds (simtime));
      wormApp->SetPatternId (patternId);

      bombs.at(0).GetChildNode(i)->AddApplication (wormApp);
      wormApp->SetUp ("ns3::UdpSocketFactory", 5000, systemId);
    }
  }

  if(systemId == 1%systemCount){
    for(uint32_t i=0; i < nChild * nInner; i++)
    {
      Ptr<Worm> wormApp = CreateObject<Worm> ();

      if (uv->GetValue(0.0, 1.0) <= vulnerability) {
        wormApp->SetVulnerable (true);
        numVulnerableNodes++;
      }

      std::string temp1 = "b" + std::to_string(i) + " " + std::to_string(systemId);
      wormApp->SetName(temp1);
      wormApp->SetSysId(systemId);

      wormApp->SetStartTime (Seconds (0.0));
      wormApp->SetStopTime (Seconds (simtime));

      bombs.at(1).GetChildNode(i)->AddApplication (wormApp);
      wormApp->SetUp ("ns3::UdpSocketFactory", 5000, systemId);
    }
  }

  if(systemId == 2%systemCount){
    for(uint32_t i=0; i < nChild * nInner; i++){
      Ptr<Worm> wormApp = CreateObject<Worm> ();

      if (uv->GetValue(0.0, 1.0) <= vulnerability) {
        wormApp->SetVulnerable (true);
        numVulnerableNodes++;
      }

      std::string temp1 = "c" + std::to_string(i) + " " + std::to_string(systemId);
      wormApp->SetName(temp1);
      wormApp->SetSysId(systemId);

      wormApp->SetStartTime (Seconds (0.0));
      wormApp->SetStopTime (Seconds (simtime));

      bombs.at(2).GetChildNode(i)->AddApplication (wormApp);
      wormApp->SetUp ("ns3::UdpSocketFactory", 5000, systemId);
    }
  }

  if(systemId == 3%systemCount){
    for(uint32_t i=0; i < nChild * nInner; i++){
      Ptr<Worm> wormApp = CreateObject<Worm> ();

      if (uv->GetValue(0.0, 1.0) <= vulnerability) {
        wormApp->SetVulnerable (true);
        numVulnerableNodes++;
      }

      std::string temp1 = "d" + std::to_string(i) + " " + std::to_string(systemId);
      wormApp->SetName(temp1);
      wormApp->SetSysId(systemId);

      wormApp->SetStartTime (Seconds (0.0));
      wormApp->SetStopTime (Seconds (simtime));

      bombs.at(3).GetChildNode(i)->AddApplication (wormApp);
      wormApp->SetUp ("ns3::UdpSocketFactory", 5000, systemId);
    }
  }

  for (int i = 0; i < 5000; ++i) {
      ns3::Simulator::Schedule(ns3::Seconds((double)i*.1), &Worm::SetNumInfected);
      ns3::Simulator::Schedule(ns3::Seconds((double)i*.01), &Worm::GetCurrentStatus);
  }

  // Populate routing tables.
  if (!nix)
  {
    std::cout << "Using IPv4 Routing!" << std::endl;
    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  }
  TIMER_NOW (t1);

  std::cerr << "actually running" << std::endl;
  Simulator::Stop(Seconds(simtime));
  Simulator::Run();
  TIMER_NOW (t2);

  double percInfected = 100.*(double)Worm::GetInfectedNodes() / (double)(nChild * nInner);
  double percVulnerable = 100.*(double)numVulnerableNodes/(double)(nChild * nInner);
  double percInfToVuln = percInfected / percVulnerable;
  cerr << "Time(s)\tInf(#)\tTot(#)\tPerc(%)\tVuln(%)\tInf/Vul(%)" << std::endl;
  cerr << setprecision(3) << Simulator::Now().GetSeconds() << "\t"
       << Worm::GetInfectedNodes() << "\t"
       << numVulnerableNodes << "\t"
       << setprecision(4) << percInfected << "\t"
       << setprecision(4) << percVulnerable << "\t"
       << setprecision(4) << percInfToVuln*100. << "\t"
       << std::endl;


  std::vector<int> infectionArray = Worm::GetInfectionArray();
  for (int i = 0; i < 5; ++i) {
    infectionArray.push_back(Worm::GetInfectedNodes());
  }

  Simulator::Destroy();

  // ****** For MPI
  // Exit the MPI execution environment
  MpiInterface::Disable ();
  double d1 = TIMER_DIFF (t1, t0), d2 = TIMER_DIFF (t2, t1);
  std::cout << "-----" << std::endl << "Runtime Stats:" << std::endl;
  std::cout << "Simulator init time: " << d1 << std::endl;
  std::cout << "Simulator run time: " << d2 << std::endl;
  std::cout << "Total elapsed time: " << d1 + d2 << std::endl;

  return 0;

#else
  NS_FATAL_ERROR ("Can't use distributed simulator without MPI compiled in");
#endif
// ******

}
