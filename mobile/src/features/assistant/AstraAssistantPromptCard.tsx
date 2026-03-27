import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useAssistantStore } from "../../store/assistantStore";
import { AstraColors } from "../../theme/astra";

export function AstraAssistantPromptCard({
  title,
  body,
  prompts,
}: {
  title: string;
  body: string;
  prompts: string[];
}) {
  const openAssistant = useAssistantStore((state) => state.openAssistant);

  return (
    <View style={styles.card}>
      <View style={styles.header}>
        <View style={styles.badge}>
          <Ionicons
            name="sparkles-outline"
            size={16}
            color={AstraColors.accentSoft}
          />
        </View>
        <View style={styles.copy}>
          <Text style={styles.title}>{title}</Text>
          <Text style={styles.body}>{body}</Text>
        </View>
      </View>

      <View style={styles.promptRow}>
        {prompts.map((prompt) => (
          <Pressable
            key={prompt}
            style={styles.promptChip}
            onPress={() => openAssistant(prompt)}
          >
            <Text style={styles.promptChipText}>{prompt}</Text>
          </Pressable>
        ))}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: 24,
    padding: 16,
    gap: 12,
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  header: {
    flexDirection: "row",
    gap: 12,
    alignItems: "flex-start",
  },
  badge: {
    width: 34,
    height: 34,
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(139,124,255,0.14)",
  },
  copy: {
    flex: 1,
    gap: 4,
  },
  title: {
    color: AstraColors.textPrimary,
    fontSize: 16,
    fontWeight: "700",
  },
  body: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    lineHeight: 18,
  },
  promptRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  promptChip: {
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 9,
    backgroundColor: "rgba(255,255,255,0.06)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  promptChipText: {
    color: AstraColors.textPrimary,
    fontSize: 12,
    fontWeight: "600",
  },
});
