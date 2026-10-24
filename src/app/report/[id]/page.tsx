import type { Metadata } from "next";
import { Suspense, use } from "react";
import { Navbar } from "@/components/site/navbar";
import { Footer } from "@/components/site/footer";
import { RealReportView } from "@/components/report/real-report-view";

export const metadata: Metadata = {
  title: "Security Scan Report — VibeShield AI",
  description: "Verified security findings across secrets, code patterns, and dependencies.",
};

function ReportBody(props: { params: Promise<{ id: string }> }) {
  const { id } = use(props.params);
  return <RealReportView jobId={id} />;
}

export default function ReportPage(props: { params: Promise<{ id: string }> }) {
  return (
    <>
      <Navbar />
      <main className="flex-1">
        <Suspense
          fallback={
            <div className="mx-auto max-w-7xl px-4 py-16 text-center text-muted-foreground">
              Loading report...
            </div>
          }
        >
          <ReportBody params={props.params} />
        </Suspense>
      </main>
      <Footer />
    </>
  );
}
