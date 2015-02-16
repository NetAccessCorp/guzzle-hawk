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
    private $credentials;
    private $hawkRequest;

    public function __construct($key, $secret, $offset = 0)
    {
        $this->key = $key;
        $this->secret = $secret;
        $this->offset = $offset;
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
            $this->credentials,
            $this->hawkRequest,
            $response->getHeader('Server-Authorization'),
            array(
                'payload' => $response->getBody(),
                'content_type' => $response->getHeader('Content-Type'),
            ));

        $response->authenticated = $authenticated;
    }

    public function signRequest(BeforeEvent $event)
    {
        $request = $event->getRequest();

        $this->credentials = $this->generateCredentials($this->key, $this->secret);

        $body = $request->getBody();

        if (!$body instanceof string)
          $body = '';

        $this->hawkRequest = $this->generateHawkRequest(
            $request->getUrl(),
            $request->getMethod(),
            $this->offset,
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

    public function generateHawkRequest(
        $url,
        $method = 'GET',
        $offset = 0,
        $ext = [],
        $payload = '',
        $contentType = ''
    ) {
        $this->client = $this->buildClient($offset);

        $requestOptions = $this->generateRequestOptions($ext, $payload, $contentType);

        $request = $this->client->createRequest(
            $this->credentials,
            $url,
            $method,
            $requestOptions
        );

        return $request;
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
