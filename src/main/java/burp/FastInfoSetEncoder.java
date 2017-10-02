package burp;

import com.sun.xml.internal.org.jvnet.fastinfoset.FastInfosetResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPOutputStream;
import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;

final class FastInfoSetEncoder {

	private final Transformer transformer;

	FastInfoSetEncoder() {
		try {
			final TransformerFactory transformerFactory = TransformerFactory.newInstance();
			transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			this.transformer = transformerFactory.newTransformer();
		} catch (final TransformerConfigurationException e) {
			throw new FastInfoSetTranslatorException("Error creating translator in the encoder", e);
		}
	}

	byte[] encode(final byte[] content, final boolean gzipped) {
		try (final InputStream input = new ByteArrayInputStream(content);
			 final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			this.transformer.transform(new StreamSource(input), new FastInfosetResult(output));
			byte[] body = output.toByteArray();
			if (gzipped) {
				body = zip(body);
			}
			return body;
		} catch (IOException | TransformerException e) {
			throw new FastInfoSetTranslatorException("Error encoding content", e);
		}
	}

	private byte[] zip(final byte[] content) {
		try (final ByteArrayOutputStream out = new ByteArrayOutputStream();
			 final ByteArrayInputStream in = new ByteArrayInputStream(content);
			 final GZIPOutputStream zipStream = new GZIPOutputStream(out)) {

			final byte[] buffer = new byte[1024];
			int length;
			while ((length = in.read(buffer)) > 0) {
				zipStream.write(buffer, 0, length);
			}
			zipStream.finish();
			return out.toByteArray();
		} catch (final IOException e) {
			throw new FastInfoSetTranslatorException("Error zipping content", e);
		}
	}

}
