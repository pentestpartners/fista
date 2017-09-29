package burp;

import java.util.List;

final class Utils {

	private Utils() {
		throw new UnsupportedOperationException("This is a utility class and should not be instantiated");
	}

	static boolean isGzipped(final IHttpRequestResponse httpRequestResponse, final boolean isRequest,
			final IExtensionHelpers helpers) {
		return hasHeader(httpRequestResponse, isRequest, helpers, "Content-Encoding:", "gzip");
	}

	static boolean isFastInfoSet(final IHttpRequestResponse httpRequestResponse, final boolean isRequest,
			final IExtensionHelpers helpers) {
		return hasHeader(httpRequestResponse, isRequest, helpers, "Content-Type:", "application/fastinfoset");
	}

	static boolean hasHeader(final IHttpRequestResponse httpRequestResponse, final boolean isRequest,
			final IExtensionHelpers helpers, final String headerName, final String headerValue) {
		if (isRequest) {
			return hasHeader(httpRequestResponse.getRequest(), isRequest, helpers, headerName, headerValue);
		}
		return hasHeader(httpRequestResponse.getResponse(), isRequest, helpers, headerName, headerValue);
	}

	static boolean hasHeader(final byte[] content, final boolean isRequest, final IExtensionHelpers helpers,
			final String headerName, final String headerValue) {
		if (isRequest) {
			final IRequestInfo request = helpers.analyzeRequest(content);
			final List<String> headers = request.getHeaders();
			return hasHeader(headers, headerName, headerValue);
		} else {
			final IResponseInfo response = helpers.analyzeResponse(content);
			final List<String> headers = response.getHeaders();
			return hasHeader(headers, headerName, headerValue);
		}
	}

	static boolean hasHeader(final List<String> headers, final String name, final String value) {
		for (final String header : headers) {
			if (header.startsWith(name)) {
				return header.contains(value);
			}
		}
		return false;
	}
}
