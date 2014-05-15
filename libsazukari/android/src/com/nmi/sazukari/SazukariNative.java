package com.nmi.sazukari;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.HashMap;

public class SazukariNative {
    static {
        System.loadLibrary("sazukarinative");
        msSocketHandleMap = new HashMap<Integer, Socket>();
    }
    
    protected static HashMap<Integer, Socket> msSocketHandleMap;
    protected static int msMaxSocketHandle;
    
    public static native int _szkrInitialize();
    public static native int _szkrNewContext(int sockHandle, ByteBuffer serverKey);
    public static native long _szkrGetSessionDataSize();
    public static native int _szkrGetSessionData(int ctxHandle, ByteBuffer outSessionData);
    public static native int _szkrResetContext(int ctxHandle);
    public static native int _szkrHandshake(int ctxHandle);
    public static native int _szkrLastError(int ctxHandle);
    public static native int _szkrResume(int ctxHandle, ByteBuffer sessionData);
    public static native int _szkrSendMessage(int ctxHandle, ByteBuffer message);
    public static native ByteBuffer _szkrAccessResponseBuffer(int ctxHandle);
    public static native void _szkrDestroyResponseBuffer(int ctxHandle);
    public static native void _szkrDestroyCtx(int ctxHandle);
    public static native void _szkrDestroy();
    
    public static int _snAddSocket(Socket s) 
    {
    	msSocketHandleMap.put(msMaxSocketHandle, s);
    	return msMaxSocketHandle++;
    }
    
    public static void _snRemoveSocket(int socketHandle)
    {
    	msSocketHandleMap.remove(socketHandle);
    }

    protected static long _snSocketRead(int sockHandle, ByteBuffer buf, long size)
    {
    	Socket s = msSocketHandleMap.get(sockHandle);
    	InputStream istream;
    	try {
    		 istream = s.getInputStream();
    	} catch (IOException e) {
    		return -1;
    	}
    	
    	byte[] mybuf = new byte[(int) size];
    	int read;
    	try {
    		read = istream.read(mybuf, 0, (int)size);
    	} catch (IOException e) {
    		return -1;
    	}
    	
    	if (read > 0) {
    		buf.put(mybuf, 0, read);
    		return read;
    	} else {
    		return -1;
    	}
    }
    
    protected static long _snSocketWrite(int sockHandle, ByteBuffer buf, long size)
    {
    	Socket s = msSocketHandleMap.get(sockHandle);
    	OutputStream ostream;
    	try {
    		 ostream = s.getOutputStream();
    	} catch (IOException e) {
    		return -1;
    	}
    	
    	byte[] mybuf = new byte[(int) size];
    	buf.get(mybuf);
    	
    	try {
    		ostream.write(mybuf, 0, (int)size);
    		return (int)size;
    	} catch (IOException e) {
    		return -1;
    	}
    }
    
}
