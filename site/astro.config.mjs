// @ts-check
import { defineConfig, passthroughImageService } from 'astro/config';
import starlight from '@astrojs/starlight';
import { satteri } from '@astrojs/markdown-satteri';
import baseLinks from './src/plugins/base-links.mjs';

// Every version of the docs is built on its own, into a directory of the gh-pages branch named after it
// (see scripts/docs-publish.sh): DOCS_VERSION is `main` or a release tag, and the base is /snitchhiker/<version>/
// (GitHub Pages serves the project under /snitchhiker/). Without DOCS_VERSION (mise run docs) the site is served at
// the root as `dev`.
const version = process.env.DOCS_VERSION || 'dev';
const base = process.env.DOCS_VERSION ? `/snitchhiker/${version}` : '/';

export default defineConfig({
	site: 'https://nikarh.github.io',
	base,
	trailingSlash: 'always',
	image: { service: passthroughImageService() },
	vite: { define: { 'import.meta.env.DOCS_VERSION': JSON.stringify(version) } },
	markdown: { processor: satteri({ mdastPlugins: [baseLinks(base)] }) },
	integrations: [
		starlight({
			title: 'Snitchhiker',
			description:
				'An interactive application firewall for Linux: every new connection is attributed to its program and decided by your rules, or by you, on the desktop or a phone.',
			favicon: '/favicon.svg',
			// The site has its own dark theme: Dark Reader leaves it alone
			head: [{ tag: 'meta', attrs: { name: 'darkreader-lock' } }],
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/nikarh/snitchhiker' }],
			editLink: { baseUrl: 'https://github.com/nikarh/snitchhiker/edit/main/site/' },
			lastUpdated: false,
			customCss: [
				'@fontsource-variable/inter/wght.css',
				'@fontsource-variable/jetbrains-mono/wght.css',
				'./src/styles/theme.css',
			],
			components: {
				SiteTitle: './src/components/SiteTitle.astro',
				Banner: './src/components/Banner.astro',
			},
			expressiveCode: {
				themes: ['github-dark-default', 'github-light-default'],
				styleOverrides: {
					borderRadius: '6px',
					codeFontSize: '0.8125rem',
					frames: { editorActiveTabIndicatorTopColor: 'transparent', shadowColor: 'transparent' },
				},
			},
			sidebar: [
				{ label: 'Getting started', items: [{ autogenerate: { directory: 'start' } }] },
				{ label: 'Install', items: [{ autogenerate: { directory: 'install' } }] },
				{ label: 'Guides', items: [{ autogenerate: { directory: 'guides' } }] },
				{ label: 'Reference', items: [{ autogenerate: { directory: 'reference' } }] },
				{ label: 'How it works', items: [{ autogenerate: { directory: 'internals' } }] },
				{ label: 'Project', collapsed: true, items: [{ autogenerate: { directory: 'project' } }] },
			],
		}),
	],
});
