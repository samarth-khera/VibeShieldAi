import type { Metadata } from "next";
import { Navbar } from "@/components/site/navbar";
import { Footer } from "@/components/site/footer";
import { ReportView } from "@/components/report/report-view";

export const metadata: Metadata = {
  title: "Demo report — VibeShield AI",
  description: "An interactive sample security report using illustrative demo data.",
};

export default function DemoReportPage() {
  return (
    <>
      <Navbar />
      <main className="flex-1">
        <ReportView />
      </main>
      <Footer />
    </>
  );
}
