import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import test from 'node:test';
import { LoginOptions } from '../src/components/login-options.js';

test('Chat renders its own employee password and captcha form with no console login link',()=>{
  const html=renderToStaticMarkup(createElement(LoginOptions,{enterpriseLoginAvailable:false}));
  for(const name of ['username','password','captcha_code'])assert.match(html,new RegExp('name="'+name+'"'));
  assert.match(html,/type="password"/);
  assert.match(html,/autocomplete="current-password"/i);
  assert.doesNotMatch(html,/from=chat|href="\/login|api\.github\.com/);
});

test('unknown or prototype-shaped OIDC error codes render a neutral page',()=>{
  for(const error of ['__proto__','toString','unrecognized-upstream-secret']){
    const html=renderToStaticMarkup(createElement(LoginOptions,{error,enterpriseLoginAvailable:false}));
    assert.match(html,/role="alert"/);
    assert.doesNotMatch(html,/unrecognized-upstream-secret|\[object Object\]/);
  }
});
