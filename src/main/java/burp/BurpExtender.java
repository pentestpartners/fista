package burp;

import java.util.Arrays;
import java.util.List;

public final class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener {

	private IExtensionHelpers helpers;
	private FastInfoSetDecoder decoder;
	private FastInfoSetEncoder encoder;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		callbacks.printOutput("Registering callbacks...");
		this.helpers = callbacks.getHelpers();
		callbacks.setExtensionName("FastInfoSet Translator and Attacker - FISTA");
		callbacks.registerHttpListener(this);
		callbacks.registerProxyListener(this);
		this.decoder = new FastInfoSetDecoder();
		this.encoder = new FastInfoSetEncoder();
	}

	/**
	 * Handle the requests from between burp & the server.
	 */
	@Override
	public void processHttpMessage(final int toolFlag, final boolean messageIsRequest,
			final IHttpRequestResponse messageInfo) {
		if (!Utils.isFastInfoSet(messageInfo, messageIsRequest, this.helpers)) {
			return;
		}
		if (messageIsRequest) {
			encodeHttpRequest(messageInfo);
		} else {
			decodeHttpResponse(messageInfo);
		}
	}

	/**
	 * Handle the requests from between the client & burp.
	 */
	@Override
	public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage message) {
		if (!Utils.isFastInfoSet(message.getMessageInfo(), messageIsRequest, this.helpers)) {
			return;
		}
		if (messageIsRequest) {
			decodeProxyRequest(message.getMessageInfo());
		} else {
			encodeProxyResponse(message.getMessageInfo());
		}
	}

	/**
	 * Decode the request from client -> burp.
	 */
	private void decodeProxyRequest(final IHttpRequestResponse httpRequestResponse) {
		final byte[] originalRequest = httpRequestResponse.getRequest();
		final IRequestInfo requestInfo = this.helpers.analyzeRequest(originalRequest);
		final List<String> headers = requestInfo.getHeaders();
		final int bodyOffset = requestInfo.getBodyOffset();

		final byte[] body = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);

		final byte[] decodedRequest =
				this.decoder.decodeMessage(body, Utils.isGzipped(httpRequestResponse, true, this.helpers));

		final byte[] newHTTPMessage = this.helpers.buildHttpMessage(headers, decodedRequest);
		httpRequestResponse.setRequest(newHTTPMessage);
	}

	/**
	 * Encode the response from burp -> client.
	 */
	private void encodeProxyResponse(final IHttpRequestResponse httpRequestResponse) {
		final byte[] originalResponse = httpRequestResponse.getResponse();
		final IResponseInfo responseInfo = this.helpers.analyzeResponse(originalResponse);
		final List<String> headers = responseInfo.getHeaders();
		final int bodyOffset = responseInfo.getBodyOffset();

		final byte[] body = Arrays.copyOfRange(originalResponse, bodyOffset, originalResponse.length);

		final byte[] encodedResponse =
				this.encoder.encode(body, Utils.isGzipped(httpRequestResponse, false, this.helpers));


		final byte[] newHTTPMessage = this.helpers.buildHttpMessage(headers, encodedResponse);
		httpRequestResponse.setResponse(newHTTPMessage);
	}

	/**
	 * Encode the request from burp -> server.
	 */
	private void encodeHttpRequest(final IHttpRequestResponse httpRequestResponse) {
		final byte[] originalRequest = httpRequestResponse.getRequest();
		final IRequestInfo requestInfo = this.helpers.analyzeRequest(originalRequest);
		final List<String> headers = requestInfo.getHeaders();
		final int bodyOffset = requestInfo.getBodyOffset();

		final byte[] body = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);

		final byte[] encodedRequest =
				this.encoder.encode(body, Utils.isGzipped(httpRequestResponse, true, this.helpers));

		final byte[] newHTTPMessage = this.helpers.buildHttpMessage(headers, encodedRequest);
		httpRequestResponse.setRequest(newHTTPMessage);
	}

	/**
	 * Decode the response from server -> burp.
	 */
	private void decodeHttpResponse(final IHttpRequestResponse httpRequestResponse) {
		final byte[] originalResponse = httpRequestResponse.getResponse();
		final IResponseInfo responseInfo = this.helpers.analyzeResponse(originalResponse);
		final List<String> headers = responseInfo.getHeaders();
		final int bodyOffset = responseInfo.getBodyOffset();

		final byte[] body = Arrays.copyOfRange(originalResponse, bodyOffset, originalResponse.length);

		final byte[] decodedMessage =
				this.decoder.decodeMessage(body, Utils.isGzipped(httpRequestResponse, false, this.helpers));

		final byte[] newHTTPMessage = this.helpers.buildHttpMessage(headers, decodedMessage);
		httpRequestResponse.setResponse(newHTTPMessage);
	}

}