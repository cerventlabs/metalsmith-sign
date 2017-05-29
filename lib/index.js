'use strict'

var openpgp = require('openpgp')
var minimatch = require('minimatch');

const path = require('path')
const util = require('util')

const debug = util.debuglog('metalsmith-sign')


module.exports = plugin;

function plugin(opts){
    opts = opts || {};
    return function (files, metalsmith, done){
        Object.keys(files).filter(minimatch.filter('**/*.@(md|markdown)')).forEach(function (file){
            if (!opts.privKey) return;
            if (!opts.passphrase) return;
            debug('signing: %s', file);
            console.log('signing: %s', file);
            var data = files[file];
            var dir = path.dirname(file).split(path.sep).join('/');
            var asc = path.basename(file, path.extname(file)) + '.asc';
            if ('.' != dir) asc = path.join(dir, asc);
            var privKeyObj = openpgp.key.readArmored(opts.privKey).keys[0];
            privKeyObj.decrypt(opts.passphrase);
            openpgp.sign({
                data: data.contents.toString(),
                privateKeys: privKeyObj,
                detached: true
            }).then(function(signed) {
                data.signature = signed.signature;
                data.fingerprint = privKeyObj.primaryKey.fingerprint;
                files[asc] = new Buffer(signed);
            });
        });
        done();
    }
}
