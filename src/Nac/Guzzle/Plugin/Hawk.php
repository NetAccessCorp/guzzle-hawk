<?php

namespace Nac\Guzzle\Plugin;


use Dflydev\Hawk\Client\ClientBuilder;
use Dflydev\Hawk\Credentials\Credentials;
use GuzzleHttp\Event\BeforeEvent;
use GuzzleHttp\Event\CompleteEvent;
use GuzzleHttp\Event\SubscriberInterface;
use GuzzleHttp\Event\RequestEvents;
use GuzzleHttp\Message\RequestInterface;
use GuzzleHttp\Message\Response;

class Hawk implements SubscriberInterface
{
    private $key;
    private $secret;
    private $offset;
    private $client;
    private $hawkRequest;
    private $credentials = null;

    public function __construct($key, $secret, $offset = 0)
    {
        $this->key = $key;
        $this->secret = $secret;
        $this->offset = $offset;
    }

    private function getCredentials()
    {
        if ($this->credentials == null)
            $this->credentials = $this->generateCredentials($this->key, $this->secret);

        return $this->credentials;
    }

    private function updateCredentials()
    {
        $this->credentials = $this->generateCredentials($this->key, $this->secret);
    }

    public function getEvents()
    {
        return [
            'before' => ['signRequest', RequestEvents::SIGN_REQUEST],
            'complete' => ['validateResponse', RequestEvents::VERIFY_RESPONSE],
        ];
    }

    public function validateResponse(CompleteEvent $event)
    {
        $response = $event->getResponse();

        if (!$response instanceof Response)
          return;

        $authenticated = $this->client->authenticate(
            $this->getCredentials(),
            $this->hawkRequest,
            $response->getHeader('Server-Authorization'),
            array(
                'payload' => $response->getBody(),
                'content_type' => $response->getHeader('Content-Type'),
            ));

        $response->addHeader('Hawk-Verification', $authenticated);
    }

    public function signRequest(BeforeEvent $event)
    {
        $request = $event->getRequest();

        $body = $request->getBody();

        if (!is_string($body))
          $body = '';

        $this->hawkRequest = $this->makeHawkRequest(
            $request->getUrl(),
            $request->getMethod(),
            [],
            $body,
            $this->extractContentType($request)
        );

        $request->setHeader(
            $this->hawkRequest->header()->fieldName(),
            $this->hawkRequest->header()->fieldValue()
        );
    }

    public function extractContentType(RequestInterface $request) {
        $headers_lower = array_change_key_case($request->getHeaders(), CASE_LOWER);

        if (array_key_exists('content-type', $headers_lower) && \
                count($headers_lower['content-type'] >= 1)) {
            return $headers_lower['content-type'][0];
        }

        return '';
    }

    public function makeHawkRequest(
        $url,
        $method = 'GET',
        $ext = [],
        $payload = '',
        $contentType = ''
    ) {
        $this->client = $this->buildClient($this->offset);

        $requestOptions = $this->generateRequestOptions($ext, $payload, $contentType);

        $request = $this->client->createRequest(
            $this->getCredentials(),
            $url,
            $method,
            $requestOptions
        );

        return $request;
    }

    // leaving the signature unchanged only for backwards compatibility
    public function generateHawkRequest(
        $key,
        $secret,
        $url,
        $method = 'GET',
        $offset = 0,
        $ext = [],
        $payload = '',
        $contentType = ''
    ) {
      if ($this->key != $key or $this->secret != $secret) {
        $this->key = $key;
        $this->secret = secret;
        $this->updateCredentials();
      }
      $this->offset = $offset;

      return $this->makeHawkRequest($url, $method, $ext, $payload, $contentType);
    }

    private function buildClient($offset)
    {
        $builder =  ClientBuilder::create();

        if ($offset) {
            $builder = $builder->setLocaltimeOffset($offset);
        }

        return $builder->build();
    }

    private function generateCredentials($key, $secret, $algorithm = 'sha256')
    {
        return new Credentials($secret, $algorithm, $key);
    }

    private function generateRequestOptions($ext, $payload, $contentType)
    {
        $requestOptions = [];
        if ($payload && $contentType) {
            $requestOptions['payload'] = $payload;
            $requestOptions['content_type'] = $contentType;
        }

        if ($ext) {
            $requestOptions['ext'] = http_build_query($ext);
        }

        return $requestOptions;
    }
} 
