package com.example.ems.util;

import com.google.zxing.*;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

public class QRGenerator {
  public static String generateQRCodeBase64(String text, int width, int height) throws Exception {
    BitMatrix bitMatrix = new MultiFormatWriter().encode(text, BarcodeFormat.QR_CODE, width, height);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    MatrixToImageWriter.writeToStream(bitMatrix, "PNG", baos);
    return Base64.getEncoder().encodeToString(baos.toByteArray());
  }
}
