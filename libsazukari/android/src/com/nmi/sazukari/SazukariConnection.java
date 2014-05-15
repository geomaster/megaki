package com.nmi.sazukari;

import java.net.Socket;
import com.nmi.sazukari.SazukariNative;

public class SazukariConnection {
	protected Socket mSocket;
	protected int mSocketHandle, mCtx;
	
	SazukariConnection(Socket s) {
		mSocket = s;
		synchronized(SazukariNative.class) {
			mSocketHandle = SazukariNative._snAddSocket(s);
			int ret = SazukariNative._szkrNewContext(mSocketHandle
			
		}
	}
}
