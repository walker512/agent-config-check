#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),{scan}=require('./core.js');
const paths=process.argv.slice(2);if(paths.length!==1||paths[0].startsWith('-')){console.error('Usage: node cli.cjs <explicit-config.json>\nRead-only, static, local. Exits 1 for high findings; 2 for input errors.');process.exit(2);}
try{if(fs.statSync(paths[0]).size>1048576)throw Error('File exceeds 1 MiB.');const report=scan(fs.readFileSync(paths[0],'utf8'));console.log(JSON.stringify(report,null,2));process.exitCode=report.counts.high?1:0;}catch(e){console.error('Input rejected: '+e.message);process.exitCode=2;}
