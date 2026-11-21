'use strict'
// Filändelser som skannern behandlar särskilt. Själva reglerna ligger i server/cheatRules.ts och hämtas från servern vid start.
const EXECUTABLE_EXT = ['exe', 'dll', 'scr', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'jar', 'lnk', 'com']
module.exports = { EXECUTABLE_EXT }
