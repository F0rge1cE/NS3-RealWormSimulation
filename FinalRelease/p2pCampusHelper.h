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

// Define an object to create a bomb topology.

#pragma once

#include "ns3/point-to-point-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv6-address-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-interface-container.h"
#include "ns3/ipv6-interface-container.h"
#include "ns3/random-variable-stream.h"

using namespace ns3;

class PointToPointCampusHelper {
public:

	PointToPointCampusHelper(uint32_t maxInner, uint32_t maxOuter, PointToPointHelper inner, PointToPointHelper outer, Ptr<UniformRandomVariable> rnd);
	/**
   * Create a PointToPointBombHelper in order to easily create
   * bomb topologies using p2p links
   *
   * \param nInner number of inner nodes in the bomb
   *
   * \param  hub2Inner PointToPointHelper used to install the links
   *                   between the inner nodes and the hub nodes
   *
   * \param nChild number of child nodes in the bomb
   *
   * \param inner2Child PointToPointHelper used to install the links
   *                    between the inner nodes and the child
   *                    nodes
   */

  PointToPointCampusHelper (uint32_t nInner,
                              PointToPointHelper hub2InnerHelper,
                              uint32_t nChild,
                              PointToPointHelper inner2ChildHelper,
                              uint32_t systemID);


  ~PointToPointCampusHelper();

	/**
   * \returns a node pointer to the hub node in the
   *          bomb, i.e., the center node
   */
  Ptr<Node> GetHub () const;

  /**
   * \param i an index into the inner of the star
   *
   * \returns a node pointer to the node at the indexed inner nodes
   */
  Ptr<Node> GetInnerNode (uint32_t i) const;

  /**
   * \param i an index into the child of the star
   *
   * \returns a node pointer to the node at the indexed child
   */
  Ptr<Node> GetChildNode (uint32_t i) const;

  /**
   * \param i index into the hub interfaces
   *
   * \returns Ipv4Address according to indexed hub interface
   */

  Ipv4Address GetHubIpv4Address (uint32_t i) const;

  /**
   * \param i index into the inner interfaces
   *
   * \returns Ipv4Address according to indexed spoke interface
   */

  Ipv4Address GetInnerIpv4Address (uint32_t i) const;

  /**
   * \param i index into the Child interfaces
   *
   * \returns Ipv4Address according to indexed child interface
   */

  Ipv4Address GetChildIpv4Address (uint32_t i) const;

  /**
   * \param i index into the hub interfaces
   *
   * \returns Ipv6Address according to indexed hub interface
   */

  Ipv6Address GetHubIpv6Address (uint32_t i) const;

  /**
   * \param i index into the inner interfaces
   *
   * \returns Ipv6Address according to indexed inner interface
   */
  Ipv6Address GetInnerIpv6Address (uint32_t i) const;

  /**
   * \param i index into the child interfaces
   *
   * \returns Ipv6Address according to indexed child interface
   */
  Ipv6Address GetChildIpv6Address (uint32_t i) const;

  /**
   * \param stack an InternetStackHelper which is used to install
   *              on every node in the bomb
   */
  void InstallStack (InternetStackHelper stack);

  /**
   * \param address an Ipv4AddressHelper which is used to install
   *                Ipv4 addresses on all the node interfaces in
   *                the bomb
   */

  void AssignIpv4Addresses (Ipv4AddressHelper address);

  // *
  //  * \param network an IPv6 address representing the network portion
  //  *                of the IPv6 Address
  //  * \param prefix the prefix length

  uint32_t InnerCount () const;

  uint32_t ChildCount () const;

private:
  NodeContainer          m_hub;             //!< Routers
  Ptr<Node>              m_hubPtr;
  NetDeviceContainer     m_hubDevices;       //!< Routers NetDevices
  NodeContainer          m_inner;            //!< Inner nodes
  NetDeviceContainer     m_innerDevices;     //!< Inner nodes NetDevices
  NodeContainer          m_child;           //!< Child nodes
  NetDeviceContainer     m_childDevices;    //!< Child nodes NetDevices

  Ipv4InterfaceContainer m_hubInterfaces;     //!< IPv4 hub interfaces
  Ipv4InterfaceContainer m_innerInterfaces;    //!< Inner interfaces (IPv4)
  Ipv4InterfaceContainer m_childInterfaces;   //!< Child interfaces (IPv4)

  Ipv6InterfaceContainer m_hubInterfaces6;     //!< IPv4 hub interfaces
  Ipv6InterfaceContainer m_innerInterfaces6;   //!< Inner interfaces (IPv6)
  Ipv6InterfaceContainer m_childInterfaces6;  //!< Child interfaces (IPv6)
};
