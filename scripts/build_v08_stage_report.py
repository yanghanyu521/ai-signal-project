"""Build the October 2026 stage report from the September Word layout."""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "16_AI信号提取统一平台阶段性项目总结_20260907.docx"
OUTPUT = ROOT / "docs" / "27_AI信号提取统一平台v0.8阶段性项目总结_20261017.docx"


def set_font(style, name: str, size: float, *, bold: bool = False) -> None:
    style.font.name = name
    style.font.size = Pt(size)
    style.font.bold = bold
    rpr = style.element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for key in ("ascii", "hAnsi", "eastAsia", "cs"):
        fonts.set(qn(f"w:{key}"), name)


def shade(cell, fill: str) -> None:
    tcpr = cell._tc.get_or_add_tcPr()
    shd = tcpr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tcpr.append(shd)
    shd.set(qn("w:fill"), fill)


def paragraph(doc: Document, text: str, *, style: str = "Normal", indent: bool = True):
    item = doc.add_paragraph(text, style=style)
    if style == "Normal":
        item.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        item.paragraph_format.first_line_indent = Inches(0.29) if indent else Inches(0)
    return item


def build() -> None:
    doc = Document(SOURCE)
    body = doc._element.body
    for element in list(body):
        if element.tag != qn("w:sectPr"):
            body.remove(element)

    set_font(doc.styles["Normal"], "宋体", 10.5)
    set_font(doc.styles["Title"], "宋体", 20, bold=True)
    set_font(doc.styles["Heading 1"], "宋体", 14, bold=True)
    set_font(doc.styles["Heading 2"], "宋体", 11.5, bold=True)
    normal = doc.styles["Normal"].paragraph_format
    normal.line_spacing = 1.15
    normal.space_after = Pt(2)
    for heading in ("Heading 1", "Heading 2"):
        doc.styles[heading].paragraph_format.space_before = Pt(8)
        doc.styles[heading].paragraph_format.space_after = Pt(3)

    title = doc.add_paragraph(style="Title")
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.add_run("AI 信号提取统一平台阶段性项目总结（v0.8）")
    date = doc.add_paragraph("统计截至 2026 年 10 月 17 日", style="Normal")
    date.alignment = WD_ALIGN_PARAGRAPH.CENTER
    date.paragraph_format.first_line_indent = Inches(0)

    doc.add_heading("1 项目概述", level=1)
    paragraph(doc, "本项目面向 AI 参与网络攻击的识别、分析与知识沉淀，从建设之初就同时覆盖恶意样本静态特征提取和对应安全报告信息抽取。平台通过 FastAPI 提供统一接口，以 SQLite 保存样本、报告、事件及其关联关系，Streamlit 界面承担测试和研判入口；样本与报告证据可以交叉确认、互为补充，并用于后续检索、关联分析和统计报告生成。")
    paragraph(doc, "v0.8 的重点是样本侧静态分析整改：保留 AI 工具链、Prompt 和 AI 生成代码文体指纹三类特征，按原始脚本源码与 PE、APK 等二进制材料分别处理，并明确候选存在、语义确认、静态调用验证的证据等级。分析不执行恶意样本；样本侧远端大模型发送默认关闭，启用后仍受材料和证据约束。报告侧继续以大模型从全文抽取目标事件事实，不在本轮重构范围。")

    doc.add_heading("2 全局态势与分析进度", level=1)
    doc.add_heading("事件库范围与实际入库", level=2)
    paragraph(doc, "截至目前，事件库共搜罗 46 起 AI 相关安全事件，这是本项目已收集范围，不代表全球穷尽总数。其中 11 起已有样本线索、具备开展静态分析的条件，对应 11 个样本家族；另 35 起暂无可分析样本。原有 9 个家族的 45 个样本已分析并保存结果。新增的 CLOSEDQUORUM 和 CL-UNK-1211 两个家族尚未下载样本，相关报告也未抽取入库，因此“可分析”不等于“已分析”。")

    table = doc.add_table(rows=1, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    table.style = "Table Grid"
    widths = (Inches(2.25), Inches(1.05), Inches(3.84))
    for column, cell, width in zip(table.columns, table.rows[0].cells, widths):
        column.width = width
        cell.width = width
    for cell, value in zip(table.rows[0].cells, ("统计项", "数量", "口径说明")):
        cell.text = value
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        shade(cell, "1F4E79")
        for run in cell.paragraphs[0].runs:
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)
    data = [
        ("已搜罗 AI 安全事件", "46", "事件库业务范围，非全球穷尽总量"),
        ("有样本、可分析事件", "11", "含新增但尚未分析的 2 起事件"),
        ("暂无样本事件", "35", "尚不能开展样本侧静态分析"),
        ("可分析样本家族", "11", "其中 9 个已分析、2 个待获取样本"),
        ("已分析样本", "45", "来自原有 9 个家族"),
        ("去重报告", "9 / 7", "事件库范围 9 份 / 已分析入库 7 份"),
        ("家族—报告映射", "11 / 9", "事件库范围 11 组 / 已入库 9 组"),
    ]
    for index, row in enumerate(data):
        cells = table.add_row().cells
        for cell, value, width in zip(cells, row, widths):
            cell.text = value
            cell.width = width
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            if index % 2:
                shade(cell, "E8F0F7")
            for para in cell.paragraphs:
                para.alignment = WD_ALIGN_PARAGRAPH.CENTER if cell is cells[1] else WD_ALIGN_PARAGRAPH.LEFT
                para.paragraph_format.space_after = Pt(0)
                for run in para.runs:
                    run.font.size = Pt(9)
    paragraph(doc, "新增两起事件分别为“CLOSEDQUORUM：由多 LLM 自主决策的 Windows 恶意植入程序”和“CL-UNK-1211：疑似 AI 辅助编写恶意脚本的政府 Linux 间谍活动”。按当前工作计划，两起事件合计有 9 个待获取样本；但《AI安全事件库.xlsx》目前仅能核对到 8 个唯一 SHA-256（6+2），剩余 1 个样本的身份需在下载前补齐核验。它们不计入 45 个已分析样本。", indent=False)
    paragraph(doc, "全局看板现按上述事件库口径显示 46、11、35、11、45、9、11 七项主指标，同时单独提示实际入库的 9 个家族、7 份去重报告和 9 组映射。既有月度趋势与模型分布图仍只统计本地已入库数据，不能解读为 46 起事件的完整趋势。", indent=False)

    capabilities_heading = doc.add_heading("3 项目现有能力与验证边界", level=1)
    capabilities_heading.paragraph_format.page_break_before = True
    doc.add_heading("恶意样本静态 AI 信号提取", level=2)
    paragraph(doc, "样本上传后先做文件识别、哈希去重与受控保存，再抽取静态材料。可信原始 Python 源码可建立 AST 与局部代码文体指纹；JavaScript、PowerShell 目前主要使用词法和片段路径。PE、APK、DEX 等二进制或封装文件只恢复受限字符串、资源及可识别成员，不把普通字符串或反编译产物直接当作原始代码。多编码扫描、分批送模和覆盖率记录改进了可见材料范围，但被截断、加密或运行时构造的内容仍可能漏检。")
    paragraph(doc, "工具链和 Prompt 既保留规则命中，也允许可选的大模型发现未知模型、SDK、私有接口及新 Prompt；结果必须回锚到原始材料。程序 Prompt、越狱 Prompt、分析器提示注入和普通文本分型处理；缺少调用关系的有效候选可以保留，但不能标为已验证调用。代码文体指纹独立于综合 AI 信号相似度，不输出未经验证的生成模型身份。")
    doc.add_heading("报告、知识库与前端应用", level=2)
    paragraph(doc, "报告侧默认通过大模型对指定目标事件进行全文分块抽取，保留模型/工具链、Prompt、组织及国家地区等原文证据。样本与报告通过明确关联后进行支持、冲突、互补和证据不足的交叉验证；人工修订的事件背景可持久写入知识库。知识库检索按样本或家族组织对应报告，关联分析分开比较工具链、Prompt 与文体特征。统一 API 提供分析、查询、统计及 Markdown 报告生成，Streamlit 界面用于操作和核查。")
    doc.add_heading("v0.8 复测结论的边界", level=2)
    paragraph(doc, "原有 9 家族、45 个相同 SHA-256 样本已完成独立的 v0.8 大模型复测，45/45 份运行状态为 completed；408/408 条模型事实可精确定位到保存的源材料，22/45 个样本具备可信源码文件级文体指纹。这些结果证明流程运行及证据定位，不证明语义判断准确。当前 606 条去重候选仍待双人标注与漏检检查，尚无经裁决金标准，不能给出工具链或 Prompt 的 Precision、Recall、F1，也不能评价具体生成模型归因准确率。复测结果保存在私有评估目录，未自动替换正式知识库的既有样本记录。")

    doc.add_heading("4 下一步工作计划", level=1)
    paragraph(doc, "首先核实新增两家族的样本清单与缺失的 1 个哈希，在受控环境获取、静态分析样本并抽取对应报告，完成证据关联后再更新正式知识库。对已有 45 个样本，优先完成候选与独立漏检区域的双人标注、冲突裁决，建立可复核的准确率指标；同时继续改进二进制材料的覆盖率、调用关系判断及大模型文体观察的误分问题。")
    paragraph(doc, "研究层面，应建立包含已知模型版本、任务、Prompt 策略和人类对照代码的参考集，验证代码文体在格式化、人工修改和未知模型条件下的可用性，当前不直接进行生成模型身份断言。知识库可逐步扩展操作手法、目标组织/行业、基础设施等抽象字段，并为每项字段保留来源、证据、置信状态和人工复核记录，以支持更稳健的跨事件相似性研判。")
    source_note = paragraph(doc, "口径依据：《AI安全事件库.xlsx》（事件库 46 条）；项目文档《v0.8 恶意样本静态 AI 信号整改说明》《v0.8 整改与 45 样本评估》；本地统计接口与已入库记录。", indent=False)
    source_note.paragraph_format.space_before = Pt(8)
    for run in source_note.runs:
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(90, 90, 90)

    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build()
