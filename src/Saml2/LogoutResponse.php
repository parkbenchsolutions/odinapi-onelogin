<?php
/**
 * This file is part of php-saml.
 *
 * (c) OneLogin Inc
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @package OneLogin
 * @author  OneLogin Inc <saml-info@onelogin.com>
 * @license MIT https://github.com/onelogin/php-saml/blob/master/LICENSE
 * @link    https://github.com/onelogin/php-saml
 */

namespace OneLogin\Saml2;

use DOMDocument;
use DOMNodeList;
use Exception;

/**
 * SAML 2 Logout Response
 */
class LogoutResponse extends AbstractResponse
{
    /**
     * Contains the ID of the Logout Response
     *
     * @var string|null
     */
    public $id;

    /**
     * Object that represents the setting info
     *
     * @var Settings
     */
    protected $_settings;

    /**
     * The decoded, unprocessed XML response provided to the constructor.
     *
     * @var string|null
     */
    protected $_logoutResponse;

    /**
     * A DOMDocument class loaded from the SAML LogoutResponse.
     *
     * @var DOMDocument|null
     */
    public $document;

    /**
     * After execute a validation process, if it fails, this var contains the cause
     *
     * @var Exception|null
     */
    private $_error;

    /**
     * Constructs a Logout Response object (Initialize params from settings and if provided
     * load the Logout Response.
     *
     * @param Settings $settings Settings.
     * @param string|null             $response An UUEncoded SAML Logout response from the IdP.
     *
     * @throws Error
     * @throws Exception
     */
    public function __construct(\OneLogin\Saml2\Settings $settings, $response = null)
    {
        $this->_settings = $settings;

        $baseURL = $this->_settings->getBaseURL();
        if (!empty($baseURL)) {
            Utils::setBaseURL($baseURL);
        }

        if ($response) {
            $decoded = base64_decode($response);
            $inflated = @gzinflate($decoded);
            if ($inflated !== false) {
                $this->_logoutResponse = $inflated;
            } else {
                $this->_logoutResponse = $decoded;
            }
            $this->document = new DOMDocument();
            $doc = Utils::loadXML($this->document, $this->_logoutResponse);

            if (false === $doc) {
                throw new Error(
                    "LogoutResponse could not be processed",
                    Error::SAML_LOGOUTRESPONSE_INVALID
                );
            }

            $this->document = $doc;

            if ($this->document->documentElement->hasAttribute('ID')) {
                $this->id = $this->document->documentElement->getAttribute('ID');
            }
        }
    }

    /**
     * Gets the Issuer of the Logout Response.
     *
     * @return string|null $issuer The Issuer
     */
    public function getIssuer()
    {
        $issuer = null;
        $issuerNodes = $this->_query('/samlp:LogoutResponse/saml:Issuer');
        if ($issuerNodes->length == 1) {
            $issuer = $issuerNodes->item(0)->textContent;
        }
        return $issuer;
    }

    /**
     * Gets the Status of the Logout Response.
     *
     * @return string|null The Status
     */
    public function getStatus()
    {
        $entries = $this->_query('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode');
        if ($entries->length != 1) {
            return null;
        }

        /** @var \DOMElement */
        $node = $entries->item(0);
        return $node->getAttribute('Value');
    }

    /**
     * Determines if the SAML LogoutResponse is valid
     *
     * @param string|null $requestId                    The ID of the LogoutRequest sent by this SP to the IdP
     * @param bool        $retrieveParametersFromServer True if we want to use parameters from $_SERVER to validate the signature
     *
     * @return bool Returns if the SAML LogoutResponse is or not valid
     *
     * @throws ValidationError
     */
    public function isValid($requestId = null, $retrieveParametersFromServer = false)
    {
        assert($this->document !== null);
        $this->_error = null;
        try {
            $idpData = $this->_settings->getIdPData();
            $idPEntityId = $idpData['entityId'];

            if ($this->_settings->isStrict()) {
                $security = $this->_settings->getSecurityData();

                if ($security['wantXMLValidation']) {
                    $res = Utils::validateXML($this->document, 'saml-schema-protocol-2.0.xsd', $this->_settings->isDebugActive(), $this->_settings->getSchemasPath());
                    if (!$res instanceof DOMDocument) {
                        throw new ValidationError(
                            "Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd",
                            ValidationError::INVALID_XML_FORMAT
                        );
                    }
                }

                // Check if the InResponseTo of the Logout Response matchs the ID of the Logout Request (requestId) if provided
                if (isset($requestId) && $this->document->documentElement->hasAttribute('InResponseTo')) {
                    $inResponseTo = $this->document->documentElement->getAttribute('InResponseTo');
                    if ($requestId != $inResponseTo) {
                        throw new ValidationError(
                            "The InResponseTo of the Logout Response: $inResponseTo, does not match the ID of the Logout request sent by the SP: $requestId",
                            ValidationError::WRONG_INRESPONSETO
                        );
                    }
                }

                // Check issuer
                $issuer = $this->getIssuer();
                if (!empty($issuer) && $issuer != $idPEntityId) {
                    throw new ValidationError(
                        "Invalid issuer in the Logout Response",
                        ValidationError::WRONG_ISSUER
                    );
                }

                $currentURL = Utils::getSelfRoutedURLNoQuery();

                if ($this->document->documentElement->hasAttribute('Destination')) {
                    $destination = $this->document->documentElement->getAttribute('Destination');
                    $this->checkDestination($destination, $currentURL, $security, 'LogoutResponse');
                }

                if ($security['wantMessagesSigned'] && !isset($_GET['Signature'])) {
                    throw new ValidationError(
                        "The Message of the Logout Response is not signed and the SP requires it",
                        ValidationError::NO_SIGNED_MESSAGE
                    );
                }
            }

            if (isset($_GET['Signature'])) {
                $signatureValid = Utils::validateBinarySign("SAMLResponse", $_GET, $idpData, $retrieveParametersFromServer);
                if (!$signatureValid) {
                    throw new ValidationError(
                        "Signature validation failed. Logout Response rejected",
                        ValidationError::INVALID_SIGNATURE
                    );
                }
            }
            return true;
        } catch (Exception $e) {
            $this->_error = $e;
            $debug = $this->_settings->isDebugActive();
            if ($debug) {
                echo htmlentities($this->_error->getMessage());
            }
            return false;
        }
    }

    /**
     * Extracts a node from the DOMDocument (Logout Response Menssage)
     *
     * @param string $query Xpath Expression
     *
     * @return DOMNodeList The queried node
     */
    private function _query($query)
    {
        assert($this->document !== null);
        return Utils::query($this->document, $query);
    }

    /**
     * Generates a Logout Response object.
     *
     * @param string $inResponseTo InResponseTo value for the Logout Response.
     *
     * @return void
     */
    public function build($inResponseTo): void
    {

        $spData = $this->_settings->getSPData();

        $this->id = Utils::generateUniqueID();
        $issueInstant = Utils::parseTime2SAML(time());
        $spEntityId = htmlspecialchars($spData['entityId'], ENT_QUOTES);
        $destination = $this->_settings->getIdPSLOResponseUrl();
        $logoutResponse = <<<LOGOUTRESPONSE
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="{$this->id}"
                  Version="2.0"
                  IssueInstant="{$issueInstant}"
                  Destination="{$destination}"
                  InResponseTo="{$inResponseTo}"
                  >
    <saml:Issuer>{$spEntityId}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
</samlp:LogoutResponse>
LOGOUTRESPONSE;
        $this->_logoutResponse = $logoutResponse;
    }

    /**
     * Returns a Logout Response object.
     *
     * @param bool|null $deflate Whether or not we should 'gzdeflate' the response body before we return it.
     *
     * @return string Logout Response deflated and base64 encoded
     */
    public function getResponse($deflate = null)
    {
        $logoutResponse = $this->_logoutResponse;
        assert($logoutResponse !== null);

        if (is_null($deflate)) {
            $deflate = $this->_settings->shouldCompressResponses();
        }

        if ($deflate) {
            $logoutResponse = gzdeflate($logoutResponse);
        }
        return base64_encode($logoutResponse);
    }

    /**
     * After execute a validation process, if fails this method returns the cause.
     *
     * @return Exception|null Cause
     */
    public function getErrorException()
    {
        return $this->_error;
    }

    /**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return null|string Error reason
     */
    public function getError()
    {
        $errorMsg = null;
        if (isset($this->_error)) {
            $errorMsg = htmlentities($this->_error->getMessage());
        }
        return $errorMsg;
    }

    /**
     * @return string|null the ID of the Response
     */
    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * Returns the XML that will be sent as part of the response
     * or that was received at the SP
     *
     * @return string|null
     */
    public function getXML()
    {
        return $this->_logoutResponse;
    }
}
