import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

describe('DV6024: sudo usage in RUN', () => {
  it('should flag sudo in RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN sudo apt-get update'), 'DV6024')).toBe(true);
  });
  it('should flag sudo with command', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN sudo rm -rf /tmp/*'), 'DV6024')).toBe(true);
  });
  it('should flag sudo -u in RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN sudo -u appuser some-command'), 'DV6024')).toBe(true);
  });
  it('should not flag RUN without sudo', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update'), 'DV6024')).toBe(false);
  });
  it('should not flag sudo in comments', () => {
    // Comments are not RUN instructions
    expect(hasRule(lintDockerfile('FROM ubuntu\n# RUN sudo apt-get update'), 'DV6024')).toBe(false);
  });
  it('should flag apt-get install sudo as well', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y sudo'), 'DV6024')).toBe(true);
  });
  it('should not flag pseudo or sudoku', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo "pseudo random"'), 'DV6024')).toBe(false);
  });
});

describe('DV1014: Use of :latest or no tag in FROM', () => {
  it('should flag FROM with no tag', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu'), 'DV1014')).toBe(true);
  });
  it('should flag FROM with :latest tag', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:latest'), 'DV1014')).toBe(true);
  });
  it('should not flag FROM with specific version', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04'), 'DV1014')).toBe(false);
  });
  it('should not flag FROM scratch', () => {
    expect(hasRule(lintDockerfile('FROM scratch'), 'DV1014')).toBe(false);
  });
  it('should not flag FROM with digest', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu@sha256:abcdef1234567890'), 'DV1014')).toBe(false);
  });
  it('should flag FROM with no tag and AS alias', () => {
    expect(hasRule(lintDockerfile('FROM node AS builder\nRUN echo hi'), 'DV1014')).toBe(true);
  });
  it('should not flag FROM referencing a stage alias', () => {
    expect(hasRule(lintDockerfile('FROM node:18 AS builder\nRUN echo build\nFROM builder'), 'DV1014')).toBe(false);
  });
  it('should flag nginx with :latest', () => {
    expect(hasRule(lintDockerfile('FROM nginx:latest'), 'DV1014')).toBe(true);
  });
  it('should not flag pinned version', () => {
    expect(hasRule(lintDockerfile('FROM nginx:1.25-alpine'), 'DV1014')).toBe(false);
  });
  it('should not flag ARG variable references', () => {
    expect(hasRule(lintDockerfile('ARG BASE_IMAGE=ubuntu:22.04\nFROM ${BASE_IMAGE}'), 'DV1014')).toBe(false);
  });
});
