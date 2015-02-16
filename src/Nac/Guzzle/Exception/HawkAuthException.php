<?php

namespace Nac\Guzzle\Exception;

use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Message\ResponseInterface;

/**
 * Exception when hawk plugin is unable to authenticate the response
 */
class HawkAuthException extends TransferException
{
    /** @var ResponseInterface */
    private $response;

    public function __construct(
        $message = '',
        ResponseInterface $response = null,
        \Exception $previous = null
    ) {
        parent::__construct($message, 0, $previous);
        $this->response = $response;
    }
    /**
     * Get the associated response
     *
     * @return ResponseInterface|null
     */
    public function getResponse()
    {
        return $this->response;
    }
}
