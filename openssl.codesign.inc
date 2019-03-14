<?php


define('CERT_INVALID_MASK', 0x80);
define('CERT_INVALID_EXPIRED', 0x81);
define('CERT_INVALID_FUTURE', 0x82);
define('CERT_INVALID_REVOKED', 0x83);


function code_sign_openssl_sign($profile, $data, $options = array()) {
  $config = config('code_sign_openssl.settings');

  $options += array(
    'cert_days' => 365,
  );

  // If not supplied in $options, create a new keypair
  if (empty($options['private_key'])) {
    $options['private_key'] = openssl_pkey_new(array(
      "digest_alg" => "sha512",
      "private_key_bits" => 4096,
      "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ));
  }

  if (empty($options['ca_cert']) || empty($options['ca_privkey'])) {
    $signing_certs = code_sign_openssl_get_signing_certs();
    $options['ca_cert'] = $signing_certs[$profile]['key_info']['cert'];
    $options['ca_privkey'] = $signing_certs[$profile]['key_info']['privkey'];
  }

  // The identity of the module
  $dn = array(
    'commonName' => $options['project']->title,
    'emailAddress' => 'modules@silkscreencms.org',
  );

  $signing_opts = array('digest_alg' => 'sha256');

  // Generate CSR
  $csr = openssl_csr_new($dn, $options['private_key'], $signing_opts);

  // Generate the Cert
  $cert = openssl_csr_sign($csr, $options['ca_cert'], $options['ca_privkey'], $options['cert_days']);

  // Export the new private key (need this?)
  openssl_pkey_export($options['private_key'], $privKey);

  // Export the new public key (need this?)
  $pubKey = openssl_pkey_get_details($options['private_key']);

  $signature = '';
  $success = openssl_sign($data, $signature, $options['private_key'], $config->get('default_hash'));
  return ($success) ? code_sign_openssl_build_signature($cert, $config->get('default_hash'), $signature) : NULL;
}

function code_sign_openssl_verify($data, $signature = NULL, $options = array()) {
  $assets = NULL;
  $ret = array(
    'valid' => array(),
    'invalid' => array(),
    'bad_ca' => array(),
    'error' => array(),
  );

  // Load the signatures, certs, and other signing assets.
  if ($signature) {
    $assets = code_sign_openssl_load_pem($signature);
  }
  else {
    // TODO: Support S/MIME inline format.
  }

  if (!is_array($assets)) {
    watchdog('codesign', 'Could not read signature: @error',
      array('@error' => $assets), WATCHDOG_ERROR);
    return FALSE;
  }

  // Verify each of the signatures
  foreach ($assets['signature'] as $sig) {

    // Each signture has a keyid that identifies the cert that signed it.
    // Make sure we have the cert for the key.
    $key_id = $sig['keyid'];
    if (!$key_id || empty($assets['certs'][$key_id])) {
      watchdog('codesign', 'Signing cert not available for key ID @key',
        array('@key' => $key_id), WATCHDOG_WARNING);
      continue;
    }

    // Grab the cert for the key.
    if(!empty($assets['certs'][$key_id]['pubkey'])) {
      $public_key = $assets['certs'][$key_id]['pubkey'];
    }
    $signing_cert = $assets['certs'][$key_id]['cert'];

    // We'll need some data from the signing cert to return to the caller.
    $parsed_cert = openssl_x509_parse($signing_cert);
    $cert_cn = $parsed_cert['subject']['CN'];
    // Fetch the public key from the signing cert.  We use this to verify the
    // signature.
    $public_key = openssl_pkey_get_public(array(0 => $signing_cert, 1 => ''));
    if (!$public_key) {
      watchdog('codesign', 'Could not get public key for cert @cn.',
        array('@cn' => $cert_cn), WATCHDOG_ERROR);
      continue;
    }

    // Check the signature is valid.
    $result = openssl_verify($data, $sig['data'], $public_key, $sig['algorithm']);
    if ($result !== 1) {
      $failure = ($result === 0) ? 'invalid' : 'error';
      $error_message  = openssl_error_string();
      $ret[$failure][] = array(
        'cn' => $cert_cn,
        'error' => $error_message,
      );
      watchdog('codesign', 'SSL signature failed for @cn (@key_id) with status @status',
        array(
          '@cn' => $cert_cn,
          '@key_id' => $key_id,
          '@status' => $error_message,
        ), WATCHDOG_ERROR);
      continue;
    }
    // Verify the signature can be traced to an accepted CA.
    $signature_chain = code_sign_openssl_cert_signed_by_valid_ca($signing_cert, $assets['certs']);

    if ($signature_chain) {
      $ret['valid'][] = array(
        'cn' => $cert_cn,
        'chain' => $signature_chain,
      );
      watchdog('codesign', 'Valid signature with @cn.', array('@cn' => $cert_cn), WATCHDOG_NOTICE);
    }
    else {
      $ret['bad_ca'][] = $cert_cn;
      watchdog('codesign', 'Valid signature, but the cert with CN @cn is not from a trusted CA.', array('@cn' => $cert_cn), WATCHDOG_WARNING);
    }
  }

  $message = t('Found @valid signatures', array('@valid' => count($ret['valid'])));
  if (!empty($ret['bad_ca'])) {
    $message .= t(', @count signed by an unknown CA', array('@count' => count($ret['bad_ca'])));
  }
  if (!empty($ret['invalid'])) {
    $message .= t(', @count with an invalid signature', array('@count' => count($ret['invalid'])));
  }
  if (!empty($ret['error'])) {
    $message .= t(', @count with other errors', array('@count' => count($ret['error'])));
  }
  $message .= '.';

  // If we have at least one good signature from a trusted CA, it is valid.
  return array(
    'success' => !empty($ret['valid']),
    'message' => $message,
    'openssl_results' => $ret,
  );
}

function code_sign_openssl_status() {
  $ca_list = code_sign_openssl_get_ca_list();

  $rows = array();
  foreach ($ca_list as $ca) {
    $rows[] = array(
      empty($ca['details']['subject']['CN']) ? $ca['details']['name'] : $ca['details']['subject']['CN'],
      $ca['details']['extensions']['subjectKeyIdentifier'],
      format_date($ca['details']['validTo_time_t']),
    );
  }

  return array(
    '#theme' => 'table',
    '#header' => array('Key name', 'Key ID', 'Expires'),
    '#rows' => $rows,
  );
}

// Private support functions beyond this point.

/**
 * Load the resources from a PEM file.
 *
 * @param string $pem
 *   The PEM formatted resources.
 *
 * @return array
 *   The cert resources, indexed by subjectKeyIdentifier.
 */
function code_sign_openssl_load_pem($pem) {
  $cert_list = array();
  $cert = '';
  foreach (explode("\n", $pem) as $line) {
    if ($cert) {
      $cert .= $line ."\n";
    }
    $matches = array();
    if (preg_match('/^-----(BEGIN) (.*)-----\r?$/', $line, $matches)) {
      $type = $matches[2];
      $cert = $line . "\n";
    }

    if ($cert && (strpos($line, '-----END') === 0)) {
      if ($line !== "-----END $type-----") {
        watchdog('codesign', 'Malformed PEM file @filename.', array('@filename' => $filename), WATCHDOG_ERROR);
        $cert = '';
        continue;
      };

      switch ($type) {
        case 'CERTIFICATE':
          $cert_res = openssl_x509_read($cert);
          $parsed_cert = openssl_x509_parse($cert_res);
          if (!empty($parsed_cert['extensions']['subjectKeyIdentifier'])) {
            $id = $parsed_cert['extensions']['subjectKeyIdentifier'];
            $cert_list['certs'][$id] = array(
              'cert' => $cert_res,
              'pubkey' => openssl_pkey_get_public($cert),
              'details' => $parsed_cert,
            );
          }
          else {
            watchdog('openssl', 'Certificate @cn has no subjectKeyIdentifier.  Ignoring.',
              array('@cn' => $parsed_cert['name']), WATCHDOG_WARNING);
          }
          break;
        case 'PUBLIC KEY':
          $key_res = openssl_pkey_get_public($cert);
          $parsed_key = openssl_pkey_get_details($key_res);
          $cert_list['public keys'][] = $key_res;
          break;
        case 'RSA PRIVATE KEY':
        case 'PRIVATE KEY':
          $key_res = openssl_pkey_get_private($cert);
          if ($key_res) {
            $cert_list['private keys'][] = $key_res;
          }
          break;
        case 'PKCS7':
          // $pkcs7_certs = array();
          // openssl_pkcs7_read($cert, $pkcs7_certs);
          // $cert_list['pkcs7'][] = $pkcs7_certs;
          watchdog('openssl', 'PKCS7 are not supported.', array(), WATCHDOG_wARNING);
          break;
        case 'CODESIGN':
          $cert_list['signature'][] = code_sign_openssl_parse_signature($cert);
          break;
        default:
          watchdog('openssl', 'Ignoring unknown resource type @type',
            array('@type' => $type), WATCHDOG_WARNING);
      }
      $cert = '';
    }
  }

  return $cert_list;
}

function code_sign_openssl_cert_signed_by_valid_ca($cert, $intermediate_certs, $depth = 0) {
  if ($depth > 5) {
    return FALSE;
  }

  $ca_list = code_sign_openssl_get_ca_list();
  $parsed_cert = openssl_x509_parse($cert);
  $authority_key_id = trim(substr($parsed_cert['extensions']['authorityKeyIdentifier'], 6));
  // Check the CA list first.
  if (in_array($authority_key_id, array_keys($ca_list))) {
    $parsed_ca_cert = openssl_x509_parse($ca_list[$authority_key_id]);
    return array($parsed_ca_cert['subject']['name'] => $ca_list[$authority_key_id]);
  }

  // Not there?  Check the intermediate certs and try again.
  if (in_array($authority_key_id, array_keys($intermediate_certs))) {
    $parsed_int_cert = openssl_x509_parse($intermediate_certs[$authority_key_id]);
    $chain = code_sign_openssl_cert_signed_by_valid_ca($intermediate_certs[$authority_key_id], $intermediate_certs, $depth+1);
    return is_array($chain) ? array_merge($chain, array($parsed_int_cert['subject']['name'] => $parsed_int_cert)) : FALSE;
  }

  return FALSE;
}

/**
 * Verify the certificate can be used for a specified purpose.  The purpose
 * string can be one of the following:
 *
 *   * 'ca' - A Certificate Authority
 *   * 'sslclient'
 *   * 'sslserver'
 *   *
 * @param $cert
 *   The certificate resource to check.
 * @param $purpose
 *   One of the purposes specified above.
 * @return
 *   TRUE if the certificate can be used for the specified purpose, FALSE
 *   otherwise.
 */
function code_sign_openssl_verify_purpose($cert, $purpose) {
  $parsed_cert = openssl_x509_parse($cert);
  return TRUE;
}

function code_sign_openssl_check_valid_cert($cert) {
  $parsed_cert = openssl_x509_parse($cert);
  $now = time();
  if ((int)$parsed_cert['validFrom_time_t'] > $now) {
    return CERT_INVALID_FUTURE;
  }
  if ((int)$parsed_cert['validTo_time_t'] < $now) {
    return CERT_INVALID_EXPIRED;
  }
  if (!code_sign_openssl_check_crl($cert, $parsed_cert)) {
    return CERT_INVALID_REVOKED;
  }
  return TRUE;
}

function code_sign_openssl_check_crl($cert, $parsed_cert = NULL) {
  if ($parsed_cert === NULL) {
    $parsed_cert = openssl_x509_parse($cert);
  }
  // TODO: Check the CRL for the cert
  return TRUE;
}

function code_sign_openssl_get_ca_list() {
  $ca_list = &backdrop_static(__FUNCTION__, array());

  if (!$ca_list) {
    // Load up the CA list.
    foreach (glob(BACKDROP_ROOT . '/core/misc/codesign/openssl/ca/*') as $file) {
      $cert_list = code_sign_openssl_load_pem(file_get_contents($file));
      foreach ($cert_list['certs'] as $id => $cert) {
        // Skip invalid certs and non-CA certs.
        if (!code_sign_openssl_check_valid_cert($cert)) {
          continue;
        }
        if (!code_sign_openssl_verify_purpose($cert, 'ca')) {
          continue;
        }
        $ca_list[$id] = $cert;
      }
    }
  }

  return $ca_list;
}

function code_sign_openssl_get_signing_certs() {
  $all_certs = &backdrop_static(__FUNCTION__, array());

  // Return cached keychain if available.
  if ($all_certs) {
    return $all_certs;
  }

  // Return nothing if there is no valid directory
  $private_key_directory = config('code_sign_openssl.settings')->get('private_key_directory');
  if (!$private_key_directory || !is_dir($private_key_directory)) {
    return array();
  }

  // Read all the PEM files, build a list of resources (certs and keys)
  $key_list = array();
  foreach(glob($private_key_directory . '/*') as $file) {
    $new_items = code_sign_openssl_load_pem(file_get_contents($file));
    foreach ($new_items as $type => $items) {
      if (empty($key_list[$type])) {
        $key_list[$type] = array();
      }
      $key_list[$type] = array_merge($key_list[$type], $items);
    }
  }

  // Pair private keys with their certs.
  foreach ($key_list['private keys'] as  $pk) {
    foreach($key_list['certs'] as $id => $c) {
      if (openssl_x509_check_private_key($c['cert'], $pk)) {
        $c['privkey'] = $pk;
        $cn = $c['details']['subject']['CN'];
        $cn .= empty($c['details']['subject']['emailAddress']) ? '' : '  (' . $c['details']['subject']['emailAddress'] . ')';
        $all_certs[$id] = array(
          'name' => $cn,
          'profile_id' => $id,
          'key_info' => $c,
        );
      }
    }
  }

  // Only certs are useful
  return $all_certs;
}

/**
 * The signature block is a base64 encoded block of data.  When decoded, the
 * data up to the first \r\n is the header, the rest of the data is the
 * signature digest itself.
 *
 * The header has the signature algorithm as a string (e.g., 'sha256'), a colon,
 * and the subjectKeyIdentifier of the signing public key, also as a string.
 * For example:
 *
 *   sha256:00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13
 *
 *   The function returns an array with the following key-value pairs:
 *   - data - The signature data in binary format.
 *   - keyid - The key ID of the signing key as a string.
 *   - algorithm - The hash algorithm used to create the signature digest.
 *
 * @param $sigdata
 *   The PEM formatted signature data from a CODESIGN block.
 * @return array
 *   An array with the signature data, key ID, and hash function.
 */
function code_sign_openssl_parse_signature($sigdata) {
  // Strip off the BEGIN CODESIGN line.
  $start = strpos($sigdata, "\n");
  $end = strpos($sigdata, "\n---", -1);
  $sigdata = substr($sigdata, $start, $end - $start);

  // Decode the meat
  $cooked = base64_decode($sigdata);
  $breakpoint = strpos($cooked, "\n");
  $header = substr($cooked, 0, $breakpoint);
  $data = substr($cooked, $breakpoint + 1);
  $header_split = strpos($header, ':');

  $signature = array(
    'algorithm' => substr($header, 0, $header_split),
    'keyid' => trim(substr($header, $header_split + 1)),
    'data' => $data,
  );

  return $signature;
}

function code_sign_openssl_build_signature($cert, $algo, $signature, $extra_certs = array()) {
  $md_names = openssl_get_md_methods();
  $algo = is_numeric($algo) ? $md_names[$algo] : $algo;

  $parsed_cert = openssl_x509_parse($cert);
  $id = $parsed_cert['extensions']['subjectKeyIdentifier'];

  $sig_data = $algo . ':' . $id . "\n" . $signature;
  $sig = "-----BEGIN CODESIGN-----\n";
  $sig .= implode("\n", str_split(base64_encode($sig_data), 64)) . "\n";
  $sig .= "-----END CODESIGN-----\n";

  // Tack on the cert with it.
  if (is_resource($cert)) {
    $cert_pem = '';
    openssl_x509_export($cert, $cert_pem);
  }
  else {
    $cert_pem = $cert;
  }

  return $sig . $cert_pem;
}

