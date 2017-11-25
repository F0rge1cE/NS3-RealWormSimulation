
#ifndef WORM_APPLICATION_H
#define WORM_APPLICATION_H

#include "ns3/core-module.h"
#include "ns3/application.h"
#include "ns3/internet-module.h"
#include "ns3/ptr.h"
#include "ns3/address.h"
#include "ns3/socket.h"
#include "ns3/event-id.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"

#include <vector>

//NS_LOG_COMPONENT_DEFINE ("ns3-worm");

/**
 * \class Worm Worm.h
 * \brief Worm application
 */
class Worm : public ns3::Application
{
public:
    static ns3::TypeId GetTypeId(void);
    Worm();
    ~Worm();

    void SetUp(std::string protocol, uint32_t infectionPort, uint32_t subnetId);

    ns3::Ipv4Address guessIP(void);

    void PrintState();
    void SetInfected(bool alreadyInfected);
    void SetVulnerable(bool vulnerable);
    void SetName(std::string name);

    void SetTotalNumOfInfected (uint32_t num);
    static void GetCurrentStatus();
    static uint32_t GetSysId();
    static void SetSysId(uint32_t id);


    // static void SetX (uint32_t xInt);
    // static void SetY (uint32_t yInt);
    // static void SetTotalNodes (uint32_t totalNodes);
    // static void SetExistNodes (uint32_t existNodes);
    static void SetNumConn (uint32_t numConn);
    static void SetPacketSize (uint32_t pktSize);
    static void SetPatternId (uint32_t patternId);
    // static uint32_t GetTotalNodes ();
    // static uint32_t GetExistNodes ();
    static uint32_t GetInfectedNodes ();
    static uint32_t GetNumConn ();
    static std::vector<int> GetInfectionArray ();
    static void SetNumInfected();

protected:
    void DoDispose (void);

    static uint32_t m_systemID;

    static uint32_t m_totalInfected;
    static uint32_t m_numConn;
    static std::vector<int> m_curInfected;
    static double m_chooseLocalPercent;

    bool m_infected;
    bool m_vulnerable;
    bool m_connected;

    uint16_t m_infectionPort;
    uint32_t m_subnetId;
    static uint32_t m_pktSize;
    uint32_t m_residualBits; //!< Number of generated, but not sent, bits
    uint32_t m_totalBytes;
    uint32_t m_addressForPattern3;
    static uint32_t m_patternId;
    ns3::Time m_lastStartTime;


    std::string m_protocol;
    std::string m_name;

    ns3::EventId m_sendEvent;
    ns3::TypeId m_typeId;
    ns3::Ptr<ns3::RandomVariableStream> m_offTime;      //!< rng for Off Time
    ns3::Ptr<ns3::Socket> m_sinkSocket;
    std::vector< ns3::Ptr<ns3::Socket> > m_onoffSocket;
    ns3::DataRate m_cbrRate;    //!< Rate that data is generated
    ns3::DataRate m_cbrRateFailSafe;

    void Write32 (uint8_t *buffer, const uint32_t data);
    void Read32 (const uint8_t *buffer, uint32_t &data);

    ns3::TracedCallback<ns3::Ptr<const ns3::Packet> > m_txTrace;

private:
    virtual void StartApplication (void);    // Called at time specified by Start
    virtual void StopApplication (void);     // Called at time specified by Stop
    void StartInfectingNodes();
    void Listen(ns3::Ptr<ns3::Socket> socket);
    void ConnectionSucceeded(ns3::Ptr<ns3::Socket> socket);
    void ConnectionFailed(ns3::Ptr<ns3::Socket> socket);
    void ScheduleStartEvent(uint32_t index);
    void SendPacket(uint32_t index);
    void StartSending(uint32_t index);
    void ScheduleNextTx(uint32_t index);
};

#endif // WORM_APPLICATION_H
