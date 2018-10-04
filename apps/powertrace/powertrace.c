/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Powertrace: periodically print out power consumption
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "sys/compower.h"
#include "powertrace.h"
#include "net/rime/rime.h"

#include <stdio.h>
#include <string.h>

struct powertrace_sniff_stats {
  struct powertrace_sniff_stats *next;
  uint32_t num_input, num_output;
  uint32_t input_txtime, input_rxtime;
  uint32_t output_txtime, output_rxtime;
#if NETSTACK_CONF_WITH_IPV6
  uint16_t proto; /* includes proto + possibly flags */
#endif
  uint16_t channel;
  uint32_t last_input_txtime, last_input_rxtime;
  uint32_t last_output_txtime, last_output_rxtime;
};

#define INPUT  1
#define OUTPUT 0

#define MAX_NUM_STATS  16

MEMB(stats_memb, struct powertrace_sniff_stats, MAX_NUM_STATS);
LIST(stats_list);

PROCESS(powertrace_process, "Periodic power output");
/*---------------------------------------------------------------------------*/
void
powertrace_print(char *str)
{
  uint64_t all_cpu, all_lpm, all_transmit, all_listen, all_time;
  uint32_t power_cpu, power_lpm, power_transmit, power_listen, all_powerinmJ , all_powerinmW;
  uint64_t cpu_consumption, lpm_consumption, transmit_consumption, listen_consumption;
  uint32_t cpu_time_per_second, lpm_time_per_second, transmit_time_per_second, listen_time_per_second;
 
  
   power_cpu = 54000; //(1.8* 3V * 10000)
   power_lpm = 1635; //(0.0545* 3V * 10000)
   power_transmit = 531000; //(17.7* 3V * 10000)
   power_listen = 600000; //(20* 3V * 10000)
   energest_flush();

   all_cpu = energest_type_time(ENERGEST_TYPE_CPU);
   all_lpm = energest_type_time(ENERGEST_TYPE_LPM);
   all_transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);
   all_listen = energest_type_time(ENERGEST_TYPE_LISTEN);
   all_time= ((all_cpu + all_lpm)/32768) + 1;// simulation time in seconds , we increase one second to be exactly compatible with simulation time
  
  // calculate the power consumption
  cpu_consumption =  (all_cpu * power_cpu) / 32768;
  lpm_consumption =  (all_lpm * power_lpm) / 32768;
  transmit_consumption =  (all_transmit * power_transmit) / 32768;
  listen_consumption =  (all_listen *  power_listen) / 32768;
  all_powerinmJ = (cpu_consumption + lpm_consumption + transmit_consumption + listen_consumption) / 10000;
  all_powerinmW = all_powerinmJ / all_time;
  //printf("all_cpu %llu all_lpm %llu all_transmit %llu all_listen %llu \n", ( all_cpu ), (all_lpm) , (all_transmit), (all_listen));
  //printf("all_cpuS %lu all_lpmS %lu all_transmitS %lu all_listenS %lu \n", ( cpu_time_per_second ), (lpm_time_per_second) , (transmit_time_per_second), ( listen_time_per_second));
  //printf("all_cpuP %llu lpmP %llu transmitP %llu listenP %llu Average Energy in mJ %lu", cpu_consumption, lpm_consumption,transmit_consumption, listen_consumption);
  //printf("Cons energy in mJ %lu Average Power in mW %d.%03d simualtionTime in S %llu \n", all_powerinmJ, (int)(all_powerinmJ / all_time), (int)((1000L * all_powerinmJ) / all_time - (all_powerinmJ / all_time) * 1000), all_time);
  printf("ResultsLog:AveragePowermW:%d.%03d\n",(int)(all_powerinmJ / all_time), (int)((1000L * all_powerinmJ) / all_time - (all_powerinmJ / all_time) * 1000));

  static uint32_t seqno;

  
  struct powertrace_sniff_stats *s;


  seqno++;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(powertrace_process, ev, data)
{
  static struct etimer periodic;
  clock_time_t *period;
  PROCESS_BEGIN();

  period = data;

  if(period == NULL) {
    PROCESS_EXIT();
  }
  etimer_set(&periodic, *period);

  while(1) {
    PROCESS_WAIT_UNTIL(etimer_expired(&periodic));
    etimer_reset(&periodic);
    powertrace_print("");
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
void
powertrace_start(clock_time_t period)
{
  process_start(&powertrace_process, (void *)&period);
}
/*---------------------------------------------------------------------------*/
void
powertrace_stop(void)
{
  process_exit(&powertrace_process);
}
/*---------------------------------------------------------------------------*/
static void
add_stats(struct powertrace_sniff_stats *s, int input_or_output)
{
  if(input_or_output == INPUT) {
    s->num_input++;
    s->input_txtime += packetbuf_attr(PACKETBUF_ATTR_TRANSMIT_TIME);
    s->input_rxtime += packetbuf_attr(PACKETBUF_ATTR_LISTEN_TIME);
  } else if(input_or_output == OUTPUT) {
    s->num_output++;
    s->output_txtime += packetbuf_attr(PACKETBUF_ATTR_TRANSMIT_TIME);
    s->output_rxtime += packetbuf_attr(PACKETBUF_ATTR_LISTEN_TIME);
  }
}
/*---------------------------------------------------------------------------*/
static void
add_packet_stats(int input_or_output)
{
  struct powertrace_sniff_stats *s;

  /* Go through the list of stats to find one that matches the channel
     of the packet. If we don't find one, we allocate a new one and
     put it on the list. */
  for(s = list_head(stats_list); s != NULL; s = list_item_next(s)) {
    if(s->channel == packetbuf_attr(PACKETBUF_ATTR_CHANNEL)
#if NETSTACK_CONF_WITH_IPV6
       && s->proto == packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID)
#endif
       ) {
      add_stats(s, input_or_output);
      break;
    }
  }
  if(s == NULL) {
    s = memb_alloc(&stats_memb);
    if(s != NULL) {
      memset(s, 0, sizeof(struct powertrace_sniff_stats));
      s->channel = packetbuf_attr(PACKETBUF_ATTR_CHANNEL);
#if NETSTACK_CONF_WITH_IPV6
      s->proto = packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID);
#endif
      list_add(stats_list, s);
      add_stats(s, input_or_output);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
input_sniffer(void)
{
  add_packet_stats(INPUT);
}
/*---------------------------------------------------------------------------*/
static void
output_sniffer(int mac_status)
{
  add_packet_stats(OUTPUT);
}
/*---------------------------------------------------------------------------*/
#if NETSTACK_CONF_WITH_RIME
static void
sniffprint(char *prefix, int seqno)
{
  const linkaddr_t *sender, *receiver, *esender, *ereceiver;

  sender = packetbuf_addr(PACKETBUF_ADDR_SENDER);
  receiver = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
  esender = packetbuf_addr(PACKETBUF_ADDR_ESENDER);
  ereceiver = packetbuf_addr(PACKETBUF_ADDR_ERECEIVER);


  printf("%lu %s %d %u %d %d %d.%d %u %u\n",
         clock_time(),
         prefix,
         linkaddr_node_addr.u8[0], seqno,
         packetbuf_attr(PACKETBUF_ATTR_CHANNEL),
         packetbuf_attr(PACKETBUF_ATTR_PACKET_TYPE),
         esender->u8[0], esender->u8[1],
         packetbuf_attr(PACKETBUF_ATTR_TRANSMIT_TIME),
         packetbuf_attr(PACKETBUF_ATTR_LISTEN_TIME));
}
/*---------------------------------------------------------------------------*/
static void
input_printsniffer(void)
{
  static int seqno = 0; 
  sniffprint("I", seqno++);

  if(packetbuf_attr(PACKETBUF_ATTR_CHANNEL) == 0) {
    int i;
    uint8_t *dataptr;

    printf("x %d ", packetbuf_totlen());
    dataptr = packetbuf_hdrptr();
    printf("%02x ", dataptr[0]);
    for(i = 1; i < packetbuf_totlen(); ++i) {
      printf("%02x ", dataptr[i]);
    }
    printf("\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
output_printsniffer(int mac_status)
{
  static int seqno = 0;
  sniffprint("O", seqno++);
}
/*---------------------------------------------------------------------------*/
RIME_SNIFFER(printsniff, input_printsniffer, output_printsniffer);
/*---------------------------------------------------------------------------*/
void
powertrace_printsniff(powertrace_onoff_t onoff)
{
  switch(onoff) {
  case POWERTRACE_ON:
    rime_sniffer_add(&printsniff);
    break;
  case POWERTRACE_OFF:
    rime_sniffer_remove(&printsniff);
    break;
  }
}
#endif /* NETSTACK_CONF_WITH_RIME */
/*---------------------------------------------------------------------------*/
RIME_SNIFFER(powersniff, input_sniffer, output_sniffer);
/*---------------------------------------------------------------------------*/
void
powertrace_sniff(powertrace_onoff_t onoff)
{
  switch(onoff) {
  case POWERTRACE_ON:
    rime_sniffer_add(&powersniff);
    break;
  case POWERTRACE_OFF:
    rime_sniffer_remove(&powersniff);
    break;
  }
}
