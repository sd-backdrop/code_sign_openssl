<?php

function code_sign_openssl_admin_form($form, &$form_state) {
  $config = config('code_sign_openssl.settings');
  $form['#config'] = 'code_sign_openssl.settings';

  $form['private_key_directory'] = array(
    '#type' => 'textfield',
    '#title' => t('Private Key Directory'),
    '#default_value' => $config->get('private_key_directory'),
  );

  $ciphers = openssl_get_cipher_methods();
  $form['default_cipher'] = array(
    '#type' => 'select',
    '#title' => t('Default Cipher'),
    '#default_value' => $config->get('default_cipher'),
    '#options' => array_combine($ciphers, $ciphers),
  );

  $hashs = openssl_get_md_methods();
  $form['default_hash'] = array(
    '#type' => 'select',
    '#title' => t('Default Hash'),
    '#default_value' => $config->get('default_hash'),
    '#options' => array_combine($hashs, $hashs),
  );

  return system_settings_form($form);
}

function code_sign_openssl_signing_key_form($form, &$form_state) {
  require_once __DIR__ . '/openssl.codesign.inc';
  $config = config('code_sign_openssl.settings');
  $form['#config'] = 'code_sign_openssl.settings';

  $keys = code_sign_openssl_get_signing_certs();
  $options = array('' => t(' - NONE - '));
  $options += array_column($keys, 'name');

  $form['default_signing_key'] = array(
    '#type' => 'select',
    '#title' => t('Default Signing Key'),
    '#options' => $options,
    '#default_value' => $config->get('default_signing_key'),
  );

  return system_settings_form($form);
}

