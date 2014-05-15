package com.nmi.sazukari;

import com.nmi.sazukari.SazukariNative;
import com.nmi.sazukari.SazukariException;

public class SazukariServerKey {
	private byte[] mByteBuffer;

	public SazukariServerKey(byte[] buf) {
		assert buf.length == SazukariServerKey.getSize();

		mByteBuffer = new byte[SazukariServerKey.getSize()];
		System.arraycopy(buf, 0, mByteBuffer, 0, mByteBuffer.length);
	}

	public SazukariServerKey(SazukariServerKey other) {
		mByteBuffer = new byte[SazukariServerKey.getSize()];
		System.arraycopy(other.mByteBuffer, 0, mByteBuffer, 0, other.mByteBuffer.length);

	}

	public static int getSize() {
		return (int) MaskomNative._szkrGetSessionDataSize();
	}

	public ByteBuffer asByteBuffer() {
		ByteBuffer buf = ByteBuffer.allocateDirect(mByteBuffer.length);
		buf.put(mByteBuffer);

		return buf;
	}

}
