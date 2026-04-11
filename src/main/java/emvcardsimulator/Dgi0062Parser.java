package emvcardsimulator;

import javacard.framework.Util;

/**
 * Parser for DGI 0062 — file structure creation, per CPS v2.0 Annex A.5 Table A-27.
 *
 * <p>Layout:
 * <pre>
 *   0062 LEN
 *     ( 62 LEN  // FCP TLV — one per EF, multiple FCPs may be concatenated
 *         80 02 NN NN          file size in bytes (mandatory, ISO 7816-4 Table 10)
 *         82 02|05 FDB DCB     file descriptor + data coding (mandatory)
 *                  [MaxRecHi MaxRecLo]   max record size (optional)
 *                  [NumRecs]             number of records (optional)
 *         88 01 SFI            short EF identifier 01..1E (mandatory)
 *         8C 04 07 A1 C2 00    security attribute compact form (optional, ignored
 *                              by EMV apps when access rules are implicit at the
 *                              DF level — see Annex A.5 body text)
 *     )+
 * </pre>
 *
 * <p>For each FCP, the parser validates the mandatory tags, derives the
 * (numRecords, maxRecordSize) pair (defaulting from tag 80 if tag 82 omits the
 * 5-byte form), and calls {@link RecordStore#preallocateSfi}.
 *
 * <p>Per CPS Annex A.5 body: "If the access rules are implicitly known by the
 * EMV application (at the DF level) then the presence of TLV tagged '8C' is not
 * required or if present it shall be ignored by the EMV application." We
 * therefore parse tag 8C just enough to walk past it without interpreting its
 * contents.
 */
public final class Dgi0062Parser {

    private Dgi0062Parser() {
        // utility
    }

    /**
     * Parse one or more 62-FCP TLVs from a DGI 0062 payload, preallocating each
     * declared SFI in the {@link RecordStore}.
     *
     * @throws javacard.framework.ISOException with 6A80 on any structural error
     */
    public static void parse(byte[] buf, short off, short len) {
        if (len <= 0) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }

        short end = (short) (off + len);
        short cursor = off;

        while (cursor < end) {
            // Outer tag must be 62
            if ((short) (cursor + 2) > end) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }
            if (buf[cursor] != (byte) 0x62) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }
            cursor++;

            // Read BER length of FCP
            short fcpLen = readBerLen(buf, cursor, end);
            cursor = (short) (cursor + berLenSize(buf, cursor));
            if ((short) (cursor + fcpLen) > end) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }

            short fcpEnd = (short) (cursor + fcpLen);

            short fileBytes = (short) 0;
            byte sfi = (byte) 0;
            byte numRecords = (byte) 0;
            short maxRecordSize = (short) 0;
            boolean haveTag82 = false;
            boolean haveTag88 = false;

            // Walk inner TLVs
            while (cursor < fcpEnd) {
                if ((short) (cursor + 2) > fcpEnd) {
                    EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
                }
                byte tag = buf[cursor++];
                short ilen = (short) (buf[cursor++] & 0xFF);
                if ((short) (cursor + ilen) > fcpEnd) {
                    EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
                }

                if (tag == (byte) 0x80) {
                    if (ilen != 2) {
                        EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
                    }
                    fileBytes = Util.getShort(buf, cursor);
                } else if (tag == (byte) 0x82) {
                    if (ilen != 2 && ilen != 5) {
                        EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
                    }
                    haveTag82 = true;
                    if (ilen == 5) {
                        // bytes 0-1 = FDB + DCB, bytes 2-3 = max rec size, byte 4 = num recs
                        maxRecordSize = Util.getShort(buf, (short) (cursor + 2));
                        numRecords = buf[(short) (cursor + 4)];
                    }
                } else if (tag == (byte) 0x88) {
                    if (ilen != 1) {
                        EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
                    }
                    sfi = buf[cursor];
                    haveTag88 = true;
                } else if (tag == (byte) 0x8C) {
                    // Security attribute compact form. Per spec body text, EMV
                    // applets ignore the contents when access rules are
                    // implicit at the DF level. We just length-check.
                    if (ilen != 4) {
                        EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
                    }
                }
                // Unknown inner tags are tolerated (forward compatibility)

                cursor = (short) (cursor + ilen);
            }

            // Mandatory tags must be present
            if (!haveTag82 || !haveTag88) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }
            if (sfi < 1 || sfi > RecordStore.MAX_SFI) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }

            // Derive numRecords / maxRecordSize from tag 80 if not provided in tag 82
            if (numRecords == 0) {
                if (fileBytes > 0 && maxRecordSize > 0) {
                    short n = (short) (fileBytes / maxRecordSize);
                    if (n < 1) {
                        n = 1;
                    }
                    if (n > RecordStore.MAX_RECORDS_PER_SFI) {
                        n = RecordStore.MAX_RECORDS_PER_SFI;
                    }
                    numRecords = (byte) n;
                } else {
                    numRecords = RecordStore.MAX_RECORDS_PER_SFI;
                }
            }
            if (maxRecordSize == 0) {
                if (fileBytes > 0 && numRecords > 0) {
                    maxRecordSize = (short) (fileBytes / numRecords);
                    if (maxRecordSize < 1) {
                        maxRecordSize = 1;
                    }
                } else {
                    maxRecordSize = RecordStore.MAX_RECORD_BYTES;
                }
            }
            if (maxRecordSize > RecordStore.MAX_RECORD_BYTES) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }

            RecordStore.preallocateSfi(sfi, numRecords, maxRecordSize);
        }
    }

    /** Read a BER-TLV length value (1, 2, or 3 bytes). */
    private static short readBerLen(byte[] buf, short off, short end) {
        if (off >= end) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }
        short b = (short) (buf[off] & 0xFF);
        if (b < (short) 0x80) {
            return b;
        }
        if (b == (short) 0x81) {
            if ((short) (off + 1) >= end) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }
            return (short) (buf[(short) (off + 1)] & 0xFF);
        }
        if (b == (short) 0x82) {
            if ((short) (off + 2) >= end) {
                EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
            }
            return Util.getShort(buf, (short) (off + 1));
        }
        EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        return 0; // unreachable
    }

    /** Number of bytes occupied by the BER length encoding starting at off. */
    private static short berLenSize(byte[] buf, short off) {
        short b = (short) (buf[off] & 0xFF);
        if (b < 0x80) {
            return (short) 1;
        }
        if (b == 0x81) {
            return (short) 2;
        }
        if (b == 0x82) {
            return (short) 3;
        }
        return (short) 1; // already errored out in readBerLen
    }
}
