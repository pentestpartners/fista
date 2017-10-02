package burp;

import com.sun.xml.internal.org.jvnet.fastinfoset.FastInfosetSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;
import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;

final class FastInfoSetDecoder {

	private final Transformer transformer;

	FastInfoSetDecoder() {
		try {
			final TransformerFactory transformerFactory = TransformerFactory.newInstance();
			transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			this.transformer = transformerFactory.newTransformer();
		} catch (final TransformerConfigurationException e) {
			throw new FastInfoSetTranslatorException("Error creating transformer in decoder", e);
		}
	}

	byte[] decodeMessage(final byte[] content, final boolean gzipped) {
		byte[] body = content;
		if (gzipped) {
			body = unzip(body);
		}
		return decodeFastInfoSetStream(body);
	}

	private byte[] decodeFastInfoSetStream(final byte[] content) {
		try (InputStream input = new ByteArrayInputStream(content);
			 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			this.transformer.transform(new FastInfosetSource(input), new StreamResult(output));
			return output.toByteArray();
		} catch (IOException | TransformerException e) {
			throw new FastInfoSetTranslatorException("Error decoding request", e);
		}
	}

	private byte[] unzip(final byte[] content) {
		try (final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(content);
			 final ByteArrayOutputStream out = new ByteArrayOutputStream();
			 final GZIPInputStream zipStream = new GZIPInputStream(byteArrayInputStream)) {
			final byte[] buffer = new byte[1024];
			int length;
			while ((length = zipStream.read(buffer)) > 0) {
				out.write(buffer, 0, length);
			}
			return out.toByteArray();
		} catch (final IOException e) {
			throw new FastInfoSetTranslatorException("Error unzipping content", e);
		}
	}

}
