package com.nmi.sazukari;

public class SazukariException extends Exception {
	private static final long serialVersionUID = -3815867096754453423L;
	
	enum ErrorCode {
		err_unknown,
		err_incompatible_versions,
		err_service_unavailable,
		err_unknown_server_errcode,
		err_invalid_state,
		err_protocol,
		err_internal,
		err_io,
		err_handhsake_needed,
		err_blacklisted_server,
		err_message_too_long,
		err_response_too_long,
		err_wrapper_error
	}

	protected ErrorCode mErrorCode;
	
	public SazukariException(ErrorCode code) {
		super(getErrorString());
		mErrorCode = code;
	}
	
	public ErrorCode getErrorCode() {
		return mErrorCode;
	}

	public String getErrorString() {
		switch (mErrorCode) {
		case err_unknown:
			return "Unknown error";
			break;

		case err_incompatible_versions:
			return "The server uses an incompatible version of the protocol";
			break;

		case err_service_unavailable:
			return "The server has signaled it cannot handle the request";
			break;

		case err_unknown_errcode:
			return "The server has sent an unknown error code";
			break;

		case err_invalid_state:
			return "Requested operation is not permitted by current state";
			break;

		case err_protocol:
			return "The server has violated the protocol";
			break;

		case err_internal:
			return "The library has encountered an internal error";
			break;

		case err_io:
			return "A socket I/O error has ocurred";
			break;

		case err_handshake_needed:
			return "A handshake is needed instead of a session resumption";
			break;

		case err_blacklisted_server:
			return "This server was compromised, cease to trust the credentials immediately!";
			break;

		case err_message_too_long:
		case err_response_too_long:
		case err_wrapper:
			return "An error has ocurred in the Java-C communication layer";
			break;

		default:
			return "Non-enumerated";
			break;
		}

	}
}
