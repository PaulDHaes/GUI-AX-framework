import { Target, ScanStatus, Severity, FleetInstance } from '../types';

export const MOCK_FLEET: FleetInstance[] = [
  { id: 'f-1', name: 'axiom-01', provider: 'DigitalOcean', ip: '104.21.55.101', region: 'NYC1', status: 'running', instanceType: 's-1vcpu-1gb', currentTask: 'nmap: example-corp.com', uptime: '2h 15m' },
  { id: 'f-2', name: 'axiom-02', provider: 'DigitalOcean', ip: '104.21.55.102', region: 'NYC1', status: 'running', instanceType: 's-1vcpu-1gb', currentTask: 'nuclei: example-corp.com', uptime: '2h 15m' },
  { id: 'f-3', name: 'axiom-03', provider: 'AWS', ip: '35.12.44.11', region: 'us-east-1', status: 'idle', instanceType: 't3.micro', uptime: '4h 30m' },
  { id: 'f-4', name: 'axiom-04', provider: 'AWS', ip: '35.12.44.12', region: 'us-east-1', status: 'idle', instanceType: 't3.micro', uptime: '4h 30m' },
  { id: 'f-5', name: 'axiom-05', provider: 'Linode', ip: '45.79.12.1', region: 'eu-central', status: 'initializing', instanceType: 'g6-standard-1', uptime: '2m' },
  { id: 'f-6', name: 'axiom-06', provider: 'Azure', ip: '20.5.1.1', region: 'westus2', status: 'terminating', instanceType: 'Standard_B1s', uptime: '5h 00m' },
];

export const MOCK_TARGETS: Target[] = [
  {
    id: 't-1',
    domain: 'example-corp.com',
    programName: 'HackerOne Public',
    lastScanDate: '2023-10-27T10:00:00Z',
    status: ScanStatus.COMPLETED,
    axiomFleetSize: 15,
    totalPorts: 142,
    subdomains: [
      {
        id: 's-1',
        hostname: 'admin.example-corp.com',
        ip: '104.21.55.2',
        location: 'San Francisco, US',
        geo: { lat: 37.7749, lng: -122.4194, country: 'US', city: 'San Francisco' },
        asn: 'AS13335',
        technologies: ['React', 'Nginx', 'Express'],
        ports: [
          { port: 80, service: 'http', isOpen: true },
          { port: 443, service: 'https', isOpen: true },
          { port: 22, service: 'ssh', isOpen: true },
        ],
        screenshot: 'https://picsum.photos/400/300?random=1'
      },
      {
        id: 's-2',
        hostname: 'dev-api.example-corp.com',
        ip: '142.250.1.1',
        location: 'Council Bluffs, US',
        geo: { lat: 41.2619, lng: -95.8608, country: 'US', city: 'Council Bluffs' },
        asn: 'AS15169',
        technologies: ['Django', 'PostgreSQL', 'Gunicorn'],
        ports: [
          { port: 443, service: 'https', isOpen: true },
          { port: 8080, service: 'http-alt', isOpen: true, banner: 'Apache Tomcat/9.0' },
        ],
        screenshot: 'https://picsum.photos/400/300?random=2'
      },
      {
        id: 's-3',
        hostname: 'jira.example-corp.com',
        ip: '54.2.1.5',
        location: 'Dublin, IE',
        geo: { lat: 53.3498, lng: -6.2603, country: 'IE', city: 'Dublin' },
        asn: 'AS16509',
        technologies: ['Atlassian Jira', 'Java'],
        ports: [
          { port: 443, service: 'https', isOpen: true },
        ],
        screenshot: 'https://picsum.photos/400/300?random=3'
      }
    ],
    vulnerabilities: [
      {
        id: 'v-1',
        name: 'CVE-2023-22515',
        severity: Severity.CRITICAL,
        description: 'Broken Access Control in Confluence Data Center and Server',
        path: '/setup/setupadministrator.action'
      },
      {
        id: 'v-2',
        name: 'Exposed Git Repository',
        severity: Severity.HIGH,
        description: 'The .git directory is accessible via HTTP.',
        path: '/.git/config'
      }
    ]
  },
  {
    id: 't-2',
    domain: 'tesla.com',
    programName: 'Bugcrowd Private',
    lastScanDate: '2023-10-26T14:30:00Z',
    status: ScanStatus.RUNNING,
    axiomFleetSize: 50,
    totalPorts: 850,
    subdomains: [
      {
        id: 's-4',
        hostname: 'shop.tesla.com',
        ip: '23.1.2.3',
        location: 'Cambridge, US',
        geo: { lat: 42.3736, lng: -71.1097, country: 'US', city: 'Cambridge' },
        asn: 'AS20940',
        technologies: ['Drupal', 'PHP'],
        ports: [
          { port: 80, service: 'http', isOpen: true },
          { port: 443, service: 'https', isOpen: true },
        ],
        screenshot: 'https://picsum.photos/400/300?random=4'
      },
       {
        id: 's-5',
        hostname: 'energysupport.tesla.com',
        ip: '104.1.2.3',
        location: 'Amsterdam, NL',
        geo: { lat: 52.3676, lng: 4.9041, country: 'NL', city: 'Amsterdam' },
        asn: 'AS20940',
        technologies: ['Salesforce', 'Next.js'],
        ports: [
          { port: 443, service: 'https', isOpen: true },
        ],
        screenshot: 'https://picsum.photos/400/300?random=5'
      }
    ],
    vulnerabilities: [
      {
        id: 'v-3',
        name: 'XSS Reflected',
        severity: Severity.MEDIUM,
        description: 'Reflected Cross-Site Scripting via query parameter "q".',
        path: '/search?q=<script>alert(1)</script>'
      }
    ]
  },
    {
    id: 't-3',
    domain: 'uber.com',
    programName: 'HackerOne Public',
    lastScanDate: '2023-10-25T09:15:00Z',
    status: ScanStatus.COMPLETED,
    axiomFleetSize: 25,
    totalPorts: 210,
    subdomains: [
      {
        id: 's-6',
        hostname: 'partners.uber.com',
        ip: '13.1.2.3',
        location: 'Singapore, SG',
        geo: { lat: 1.3521, lng: 103.8198, country: 'SG', city: 'Singapore' },
        asn: 'AS16509',
        technologies: ['React', 'Go'],
        ports: [
          { port: 443, service: 'https', isOpen: true },
        ],
        screenshot: 'https://picsum.photos/400/300?random=6'
      }
    ],
    vulnerabilities: []
  }
];