<?php

namespace OneLogin\Saml2;

abstract class AbstractResponse
{
    protected function checkDestination(string $destination, string $currentURL, array $security, string $what): void
    {
        if (empty($destination)) {
            if (!$security['relaxDestinationValidation']) {
                throw new ValidationError(
                    "The response has an empty Destination value",
                    ValidationError::EMPTY_DESTINATION
                );
            }
        } else {
            $destination = parse_url($destination, PHP_URL_HOST) . parse_url($destination, PHP_URL_PATH);
            $currentURL = parse_url($currentURL, PHP_URL_HOST) . parse_url($currentURL, PHP_URL_PATH);
            $urlComparisonLength = $security['destinationStrictlyMatches'] ? strlen($destination) : strlen($currentURL);
            if (strncmp($destination, $currentURL, $urlComparisonLength) !== 0) {
                $currentURLNoRouted = Utils::getSelfURLNoQuery();
                $urlComparisonLength = $security['destinationStrictlyMatches'] ? strlen($destination) : strlen($currentURLNoRouted);
                if (strncmp($destination, $currentURLNoRouted, $urlComparisonLength) !== 0) {
                    throw new ValidationError(
                        sprintf("The %s was received at %s instead of %s", $what, $currentURL, $destination),
                        ValidationError::WRONG_DESTINATION
                    );
                }
            }
        }
    }
}
