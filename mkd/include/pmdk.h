/* PEGASUS MINION DEVELOPMENT KIT(tm)
 *
 * Intense feelings of grandiosity ensue!
 */
#ifndef __PMDK_H__
#define __PMDK_H_
#include <arpa/inet.h>
#include <megaki.h>
#define PEGASUS_GUID_BYTES              8
#define pk __attribute__((__packed__))

enum pegasus_reqtype {
  PEGASUS_REQ_START = 0x01,
  PEGASUS_REQ_QUIT = 0x02,
  PEGASUS_REQ_HANDLE = 0x03
};

enum pegasus_resptype {
  PEGASUS_RESP_START_OK = 0x01,
  PEGASUS_RESP_START_FAIL = 0x02,
  PEGASUS_RESP_QUIT_OK = 0x03,
  PEGASUS_RESP_HANDLE_OK = 0x04,
  PEGASUS_RESP_HANDLE_FAIL = 0x05
};

/* Request header: sent first, contains the type of the request */
typedef struct pk pegasus_req_hdr_t {
  byte type;
} pegasus_req_hdr_t;

/* Response header: sent first, contains the type of the response */
typedef struct pk pegasus_resp_hdr_t {
  byte type;  
} pegasus_resp_hdr_t;

/* Pegasus GUID structure, contains an 8-byte GUID */
typedef struct pk pegasus_guid_t {
  byte data[PEGASUS_GUID_BYTES];
} pegasus_guid_t;

/* Payload sent by Yami: Megaki token and IP address forwarded from Yugi */
typedef struct pk pegasus_yami_payload_t {
  struct sockaddr_in  client_ip;
  mgk_token_t         megaki_token;
} pegasus_yami_payload_t;

/* Context start request, contains GUID & payload size which follows */
typedef struct pk pegasus_start_req_t {
  pegasus_guid_t guid;
  length_t       datasize;
  /* follows: datasize bytes of payload */
} pegasus_start_req_t;

/* Context start response, contains nothing (for now) */
typedef struct pk pegasus_start_resp_t {

} pegasus_start_resp_t;

/* Quit request, contains no actual additional data (for now) except for
 * the GUID */
typedef struct pk pegasus_quit_req_t {
  pegasus_guid_t guid;
} pegasus_quit_req_t;

/* Quit response, contains nothing (for now) */
typedef struct pegasus_quit_resp_t {

} pegasus_quit_resp_t;

/* Message handle request, contains the GUID of this context (useful for
 * multiple-context-single-minion architectures) and message size, while the
 * message data follows */
typedef struct pk pegasus_handle_req_t {
  pegasus_guid_t guid;
  length_t       msgsize;
  /* follows: message of msgsize bytes */
} pegasus_handle_req_t;

/* Message handle response, contains GUID and response size, while the response
 * data follows */
typedef struct pegasus_handle_resp_t {
  length_t       respsize;
  /* follows: response of respsize bytes */
} pegasus_handle_resp_t;

#endif // __PMDK_H__
