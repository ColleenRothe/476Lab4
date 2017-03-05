
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

public class scannerfinder {

    static int count = 0;
    static int ack_count = 0;
    static HashMap <String, List<Integer>> map = new HashMap();
    static List <String> ips = new ArrayList<String>();

    public static void main(String[] args) {

        /* 
         * Example #1 open offline capture file for reading packets. 
         */
        final String FILENAME = "capture.pcap";
        final StringBuilder errbuf = new StringBuilder();

        final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
        if (pcap == null) {
            System.err.println(errbuf); // Error is stored in errbuf if any  
            return;
        }
        pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {

            /**
             * We purposely define and allocate our working tcp header
             * (accessor) outside the dispatch function and thus the libpcap
             * loop, as this type of object is reusable and it would be a very
             * big waist of time and resources to allocate it per every dispatch
             * of a packet. We mark it final since we do not plan on allocating
             * any other instances of Tcp.
             */
            final Tcp tcp = new Tcp();
            final Ip4 ip = new Ip4();

            /* 
             * Same thing for our http header 
             */
            final Http http = new Http();

            /**
             * Our custom handler that will receive all the packets libpcap will
             * dispatch to us. This handler is inside a libpcap loop and will
             * receive exactly 10 packets as we specified on the Pcap.loop(10,
             * ...) line above.
             *
             * @param packet a packet from our capture file
             * @param errbuf our custom user parameter which we chose to be a
             * StringBuilder object, but could have chosen anything else we
             * wanted passed into our handler by libpcap
             */
            public void nextPacket(JPacket packet, StringBuilder errbuf) {

                /* 
                 * Here we receive 1 packet at a time from the capture file. We are 
                 * going to check if we have a tcp packet and do something with tcp 
                 * header. We are actually going to do this twice to show 2 different 
                 * ways how we can check if a particular header exists in the packet and 
                 * then get that header (peer header definition instance with memory in 
                 * the packet) in 2 separate steps. 
                 */
                if (packet.hasHeader(Tcp.ID)) {
                    System.out.println("yes!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    /* 
                     * Now get our tcp header definition (accessor) peered with actual 
                     * memory that holds the tcp header within the packet. 
                     */
                    packet.getHeader(tcp);
                    
                    String sourceIP = "";
                    String destinationIP = "";
                    
                    if(packet.hasHeader(ip)){
                        //System.out.println("destination ip: "+ packet.getHeader(ip).destination());
                        //System.out.println("source ip: "+ packet.getHeader(ip).source());
                         sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source());
                         destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination());

                        System.out.println("source IP: "+sourceIP);
                        System.out.println("des IP: "+destinationIP);
                        
    
                    }

//                    System.out.printf("tcp.dst_port=%d%n", tcp.destination());
//                    System.out.printf("tcp.src_port=%d%n", tcp.source());
                   // System.out.printf("tcp.ack=%x%n", tcp.ack());
                    System.out.println("tcp SYN:  " + tcp.flags_SYN());
                    System.out.println("tcp ACK:  " + tcp.flags_ACK());
                   
                    if (tcp.flags_SYN()) {
                        count = count + 1;
                        //this is a syn-ack
                        if (tcp.flags_ACK()) {
                            ack_count++;
                            System.out.println("ITS A SYN ACK");
                            
                            if(map.containsKey(destinationIP)){
                                 List<Integer> tempList = map.get(destinationIP);
                                int syn = tempList.get(0);
                                int syn_ack = tempList.get(1);
                                tempList.set(1, syn_ack+1);
                                map.put(destinationIP, tempList);
                                
                            }
                            else{
                                List<Integer> tempList = new ArrayList<Integer>();
                                tempList.set(0,0);
                                tempList.set(1,1);
                                map.put(destinationIP, tempList);
                                
                            }
                            
                            
                        } //this is just a syn
                        else{
                            if(map.containsKey(sourceIP)){
                                List<Integer> tempList = map.get(sourceIP);
                                int syn = tempList.get(0);
                                int syn_ack = tempList.get(1);
                                tempList.set(0, syn+1);
                                map.put(sourceIP, tempList); 
                            }
                            else{
                                List<Integer> tempList = new ArrayList<Integer>();
                                tempList.set(0,1);
                                tempList.set(1,0);
                                map.put(sourceIP, tempList);
                            }
                        }
                    }
                    
                    
                }

                /* 
                 * An easier way of checking if header exists and peering with memory 
                 * can be done using a conveniece method JPacket.hasHeader(? extends 
                 * JHeader). This method performs both operations at once returning a 
                 * boolean true or false. True means that header exists in the packet 
                 * and our tcp header difinition object is peered or false if the header 
                 * doesn't exist and no peering was performed. 
                 */
//                if (packet.hasHeader(tcp)) {
//                    System.out.printf("tcp header::%s%n", tcp.toString());
//                }

            }

        }, errbuf);

        pcap.close();
        System.out.println("# of syn: " + count);

        System.out.println("SYN ACK COUNT: " + ack_count);
        
        compareList();

    }
    
    public static void compareList(){
        //for each key in the key set
        List<String> keyList = new ArrayList<String> ();
        keyList.addAll(map.keySet());
        for(int i = 0; i<keyList.size();i++){
            List<Integer> tempList = map.get(keyList.get(i));
            int syn = tempList.get(0);
            int syn_ack = tempList.get(1);
            
            if(syn >= (syn_ack*3)){
                ips.add(keyList.get(i));
            }
            
        }
        System.out.println("LIST OF IP ADDRESSES");
        for(int j=0;j<ips.size();j++){
            System.out.println(ips.get(j));
        }
    }
    
    
    
}

