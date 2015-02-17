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
use Nac\Guzzle\Exception\HawkAuthException;

class Hawk implements SubscriberInterface
{
    private $key;
    private $secret;
    private $offset;
    private $client;
    private $hawkRequest;
    private $credentials;
    private $validate_response;

    public function __construct($key, $secret, $offset = 0, $validate_response = false)
    {
        $this->key = $key;
        $this->secret = $secret;
        $this->offset = $offset;
        $this->validate_response = $validate_response;
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
        // skip if response validation is disabled
        if (!$this->validate_response) {
            return;
        }

        // get response object
        $response = $event->getResponse();
        if (!$response instanceof Response) {
            return;
        }

        // get server signature
        $signature = $response->getHeader('Server-Authorization');
        if (!$signature) {
            // allow 4xx/5xx responses without authorization
            if ($response->getStatusCode() >= 400 && $response->getStatusCode() < 600) {
                return;
            }

            throw new HawkAuthException(
                'Hawk Server-Authorization header not found',
                $response
            );
        }

        // validate signature
        $authenticated = $this->client->authenticate(
            $this->getCredentials(),
            $this->hawkRequest,
            $signature,
            array(
                'payload' => $response->getBody(),
                'content_type' => $response->getHeader('Content-Type'),
            )
        );
        if (!$authenticated) {
            throw new HawkAuthException(
                'Response has not passed hawk validation',
                $response
            );
        }
    }

    public function signRequest(BeforeEvent $event)
    {
        $request = $event->getRequest();

        $body = $request->getBody();

        if (!isset($body))
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
