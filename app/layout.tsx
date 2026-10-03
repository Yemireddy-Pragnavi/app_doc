import type { Metadata } from 'next';
import './globals.css';
export const metadata:Metadata={title:'App Security Doctor — Know before you deploy',description:'Evidence-backed security diagnosis for the applications you build. Understand your stack, prioritize risks, and deploy with clarity.',icons:{icon:'/favicon.svg'}};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en" className="dark"><body>{children}</body></html>}
