/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 *
 * Author: Nan Li <nli78@gatech.edu>
 */

#include <cmath>
#include <iostream>
#include <sstream>

#include "ns3/log.h"
#include "ns3/constant-position-mobility-model.h"

#include "ns3/node-list.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/vector.h"
#include "ns3/ipv6-address-generator.h"

#include "p2pCampusHelper.h"

using namespace ns3;

PointToPointCampusHelper::PointToPointCampusHelper(uint32_t maxInner, uint32_t maxOuter, PointToPointHelper inner, PointToPointHelper outer, Ptr<UniformRandomVariable> rnd) {

}

PointToPointCampusHelper::PointToPointCampusHelper (uint32_t nInner,
                              PointToPointHelper hub2InnerHelper,
                              uint32_t nChild,
                              PointToPointHelper inner2ChildHelper,
                              uint32_t systemID){
  m_hubPtr = CreateObject<Node> (systemID);
  m_hub.Add (m_hubPtr);
  m_inner.Create (nInner, systemID);
  m_child.Create (nChild * nInner, systemID);

  for (uint32_t i = 0; i < m_inner.GetN (); ++i)
    {
      NetDeviceContainer ndHub2Inner = hub2InnerHelper.Install (m_hub.Get (0), m_inner.Get (i));
      m_hubDevices.Add (ndHub2Inner.Get (0));
      m_innerDevices.Add (ndHub2Inner.Get (1));

      for(uint32_t j = 0; j < nChild; ++j){
        NetDeviceContainer ndInner2Child = inner2ChildHelper.Install (m_inner.Get (i), m_child.Get (nChild * i + j));
        m_innerDevices.Add (ndInner2Child.Get (0));
        m_childDevices.Add (ndInner2Child.Get (1));
      }
    }
}

PointToPointCampusHelper::~PointToPointCampusHelper() {

}

Ptr<Node>
PointToPointCampusHelper::GetHub () const{
  return m_hub.Get (0);
}

Ptr<Node>
PointToPointCampusHelper::GetInnerNode (uint32_t i) const{
  return m_inner.Get (i);
}

Ptr<Node>
PointToPointCampusHelper::GetChildNode (uint32_t i) const{
  return m_child.Get (i);
}

Ipv4Address
PointToPointCampusHelper::GetHubIpv4Address (uint32_t i) const{
  return m_hubInterfaces.GetAddress (i);
}

Ipv4Address
PointToPointCampusHelper::GetInnerIpv4Address (uint32_t i) const{
  return m_innerInterfaces.GetAddress (i);
}

Ipv4Address
PointToPointCampusHelper::GetChildIpv4Address (uint32_t i) const{
  return m_childInterfaces.GetAddress (i);
}

Ipv6Address
PointToPointCampusHelper::GetHubIpv6Address (uint32_t i) const{
  return m_hubInterfaces6.GetAddress (i, 1);
}

Ipv6Address
PointToPointCampusHelper::GetInnerIpv6Address (uint32_t i) const{
  return m_innerInterfaces6.GetAddress(i, 1);
}

Ipv6Address
PointToPointCampusHelper::GetChildIpv6Address (uint32_t i) const{
  return m_childInterfaces6.GetAddress(i, 1);
}

void
PointToPointCampusHelper::InstallStack (InternetStackHelper stack){
  stack.Install(m_hub);
  stack.Install(m_inner);
  stack.Install(m_child);
}

void
PointToPointCampusHelper::AssignIpv4Addresses (Ipv4AddressHelper address){
  uint32_t nChild = m_child.GetN () / m_inner.GetN ();

  for (uint32_t i = 0; i < m_inner.GetN (); ++i)
    {
      m_hubInterfaces.Add (address.Assign (m_hubDevices.Get (i)));
      m_innerInterfaces.Add (address.Assign (m_innerDevices.Get (i * (nChild + 1))));

      address.NewNetwork ();
      // std::cout << m_hubInterfaces.GetAddress(i) << std::endl;
      // std::cout << m_innerInterfaces.GetAddress(3*i) << std::endl;

      for (uint32_t j = 0; j < nChild; ++j){
        m_innerInterfaces.Add (address.Assign (m_innerDevices.Get (i * (nChild + 1) + (j + 1))));
        m_childInterfaces.Add (address.Assign (m_childDevices.Get (i * nChild + j)));

        address.NewNetwork ();
        // std::cout << m_innerInterfaces.GetAddress(i*3+j+1) << std::endl;
        // std::cout << m_childInterfaces.GetAddress(i*2 + j) << std::endl;

      }
      // address.NewNetwork ();
    }

}



uint32_t
PointToPointCampusHelper::InnerCount() const{
	return m_inner.GetN ();
}

uint32_t
PointToPointCampusHelper::ChildCount() const{
	return m_child.GetN ();
}
