import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Bot, Plus, Send, Trash2 } from 'lucide-react';

import { assistant as assistantApi, lastAssessment } from '../api/client';
import { Banner, Card, EmptyState, Spinner } from '../components/ui';
import {
  CardView,
  CitationList,
  NoUnsafeContent,
  OriginBadge,
  ToolResultIcon,
} from '../components/chat';

function fmtTime(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleTimeString();
  } catch (err) {
    return '';
  }
}

function MessageBubble({ message, onNavigate }) {
  const mine = message.role === 'user';
  if (mine) {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-xl bg-brand-600 px-4 py-2.5 text-sm text-white shadow-card">
          <p className="whitespace-pre-wrap">{message.content}</p>
          <p className="mt-1 text-right text-[11px] text-brand-100">{fmtTime(message.created_at)}</p>
        </div>
      </div>
    );
  }
  return (
    <div className="flex justify-start">
      <div className="max-w-[95%] flex-1 rounded-xl border border-ink-hairline bg-surface-raised px-4 py-3 shadow-card">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <Bot className="h-4 w-4 text-brand-500" aria-hidden="true" />
          <OriginBadge verified={message.verified} model={message.model} />
          {message.intent ? <span className="chip-neutral">{message.intent}</span> : null}
          {(message.tool_calls || []).length ? (
            <span className="flex items-center gap-1 text-xs text-ink-muted">
              {message.tool_calls.map((t, i) => (
                <span key={i} className="inline-flex items-center gap-1 font-mono">
                  <ToolResultIcon ok={t.ok} /> {t.tool}
                </span>
              ))}
            </span>
          ) : null}
        </div>
        <p className="whitespace-pre-wrap text-sm text-ink-primary">{message.content}</p>
        <CitationList citations={message.citations} />
        {(message.cards || []).length ? (
          <div className="mt-3 space-y-2">
            {message.cards.map((card, i) => (
              <CardView key={i} card={card} onNavigate={onNavigate} />
            ))}
          </div>
        ) : null}
        <p className="mt-2 text-[11px] text-ink-muted">{fmtTime(message.created_at)}</p>
      </div>
    </div>
  );
}

function ConversationList({ conversations, activeId, onSelect, onDelete }) {
  if (conversations.length === 0) {
    return <p className="text-sm text-ink-muted">No conversations yet.</p>;
  }
  return (
    <ul className="max-h-[300px] space-y-1 overflow-y-auto">
      {conversations.map((c) => (
        <li
          key={c.conversation_id}
          className={`group flex items-center gap-1 rounded-lg px-2 py-2 text-sm ${
            c.conversation_id === activeId
              ? 'bg-brand-600 text-white'
              : 'text-ink-secondary hover:bg-brand-50'
          }`}
        >
          <button
            type="button"
            className="min-w-0 flex-1 truncate text-left"
            onClick={() => onSelect(c.conversation_id)}
          >
            {c.title || 'New conversation'}
          </button>
          <button
            type="button"
            aria-label="Delete conversation"
            className={`rounded p-1 ${
              c.conversation_id === activeId
                ? 'hover:bg-brand-500'
                : 'hover:bg-brand-100'
            }`}
            onClick={() => onDelete(c.conversation_id)}
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </li>
      ))}
    </ul>
  );
}

export default function Assistant({ notify, onNavigate, compact = false }) {
  const [conversations, setConversations] = useState([]);
  const [activeId, setActiveId] = useState('');
  const [messages, setMessages] = useState([]);
  const [assessmentId, setAssessmentId] = useState(() => lastAssessment());
  const [input, setInput] = useState('');
  const [prompts, setPrompts] = useState([]);
  const [working, setWorking] = useState(false);
  const [streamingText, setStreamingText] = useState('');
  const [pendingCards, setPendingCards] = useState([]);
  const [pendingIntent, setPendingIntent] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showList, setShowList] = useState(false);
  const bottomRef = useRef(null);

  const refreshList = useCallback(async () => {
    const list = await assistantApi.listConversations();
    setConversations(list.conversations || []);
    return list.conversations || [];
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([assistantApi.prompts(), assistantApi.listConversations()])
      .then(([promptList, convList]) => {
        if (cancelled) return;
        setPrompts(promptList.prompts || []);
        setConversations(convList.conversations || []);
        if (convList.conversations && convList.conversations.length) {
          setActiveId(convList.conversations[0].conversation_id);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const loadConversation = useCallback(
    async (id) => {
      if (!id) return;
      setError('');
      try {
        const body = await assistantApi.getConversation(id);
        setActiveId(id);
        setMessages(body.messages || []);
        if (body.assessment_id) setAssessmentId(body.assessment_id);
      } catch (err) {
        setError(err.message);
      }
    },
    []
  );

  useEffect(() => {
    if (activeId && !messages.length) loadConversation(activeId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId]);

  useEffect(() => {
    if (bottomRef.current && typeof bottomRef.current.scrollIntoView === 'function') {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, streamingText, working]);

  const startNew = async () => {
    setError('');
    try {
      const body = await assistantApi.createConversation({
        assessmentId: assessmentId.trim() || undefined,
      });
      setConversations((prev) => [body, ...prev]);
      setActiveId(body.conversation_id);
      setMessages([]);
      setPendingCards([]);
      setStreamingText('');
    } catch (err) {
      setError(err.message);
    }
  };

  const removeConversation = async (id) => {
    setError('');
    try {
      await assistantApi.deleteConversation(id);
      setConversations((prev) => prev.filter((c) => c.conversation_id !== id));
      if (id === activeId) {
        setActiveId('');
        setMessages([]);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const send = async (text) => {
    const content = (text ?? input).trim();
    if (!content || working) return;
    setError('');
    let conversationId = activeId;
    try {
      if (!conversationId) {
        const body = await assistantApi.createConversation({
          assessmentId: assessmentId.trim() || undefined,
        });
        conversationId = body.conversation_id;
        setActiveId(conversationId);
        setConversations((prev) => [body, ...prev]);
        setMessages([]);
      }
    } catch (err) {
      setError(err.message);
      return;
    }
    const optimistic = {
      message_id: `local-${Date.now()}`,
      role: 'user',
      content,
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, optimistic]);
    setInput('');
    setWorking(true);
    setStreamingText('');
    setPendingCards([]);
    setPendingIntent('');
    try {
      const done = await assistantApi.sendMessageStream(
        conversationId,
        { message: content, assessmentId: assessmentId.trim() || undefined },
        {
          onHeader: (header) => {
            setPendingIntent(header.intent || '');
            setPendingCards(header.cards || []);
            if (header.task && header.task.assessment_id) {
              setAssessmentId(header.task.assessment_id);
            }
          },
          onDelta: (delta) => setStreamingText((prev) => prev + delta),
        }
      );
      // Re-read the persisted thread so ids, citations and cards match the server.
      const body = await assistantApi.getConversation(conversationId);
      setMessages(body.messages || []);
      if (body.assessment_id) setAssessmentId(body.assessment_id);
      refreshList().catch(() => {});
      if (!done) {
        notify('Reply finished without a completion marker; thread reloaded.', 'info');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setWorking(false);
      setStreamingText('');
      setPendingCards([]);
      setPendingIntent('');
    }
  };

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  if (loading) {
    return (
      <Card>
        <p className="flex items-center gap-2 text-sm text-ink-secondary">
          <Spinner /> Loading assistant…
        </p>
      </Card>
    );
  }

  const assessmentField = (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-ink-secondary">
        Assessment context (optional)
      </span>
      <input
        className="field font-mono text-xs"
        value={assessmentId}
        onChange={(e) => setAssessmentId(e.target.value)}
        placeholder="asm-…"
        spellCheck={false}
      />
    </label>
  );

  return (
    <div className="space-y-4">
      {compact ? null : (
        <header>
          <h2 className="text-xl font-bold text-ink-primary">AI Security Assistant</h2>
          <p className="mt-1 text-sm text-ink-muted">
            Conversational copilot over live audits, findings and remediation. Verified tool
            output is labelled; everything else is AI-generated.
          </p>
        </header>
      )}

      {error ? <Banner tone="error" title="Request failed">{error}</Banner> : null}

      {compact ? (
        <div className="flex items-center gap-2">
          <button type="button" className="btn-ghost" onClick={() => setShowList((v) => !v)}>
            Conversations ({conversations.length})
          </button>
          <button type="button" className="btn-ghost" onClick={startNew} title="New conversation">
            <Plus className="h-4 w-4" /> New
          </button>
          <div className="min-w-0 flex-1">{assessmentField}</div>
        </div>
      ) : null}
      {compact && showList ? (
        <Card>
          <ConversationList
            conversations={conversations}
            activeId={activeId}
            onSelect={(id) => {
              loadConversation(id);
              setShowList(false);
            }}
            onDelete={removeConversation}
          />
        </Card>
      ) : null}

      <div className={compact ? 'grid gap-4' : 'grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)]'}>
        {compact ? null : (
          <Card
            title="Conversations"
            actions={
              <button type="button" className="btn-ghost" onClick={startNew} title="New conversation">
                <Plus className="h-4 w-4" /> New
              </button>
            }
          >
            <ConversationList
              conversations={conversations}
              activeId={activeId}
              onSelect={loadConversation}
              onDelete={removeConversation}
            />
            <div className="mt-4 border-t border-ink-hairline pt-3">
              {assessmentField}
            </div>
          </Card>
        )}

        <Card className={`flex flex-col ${compact ? 'min-h-[420px]' : 'min-h-[560px]'}`}>
          {messages.length === 0 && !working ? (
            <div className="flex flex-1 flex-col">
              <EmptyState icon={Bot} title="Ask about your API security posture">
                Start with a suggested prompt, or ask anything — findings, threat
                models, fixes, or an executive summary.
              </EmptyState>
              {prompts.length ? (
                <div className="mt-4 flex flex-wrap gap-2">
                  {prompts.map((p) => (
                    <button
                      key={p}
                      type="button"
                      className="btn-ghost"
                      onClick={() => send(p)}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              ) : null}
              <div className="mt-4">
                <NoUnsafeContent />
              </div>
            </div>
          ) : (
            <div className={`flex-1 space-y-4 overflow-y-auto pr-1 ${compact ? 'max-h-[380px]' : 'max-h-[520px]'}`}>
              {messages.map((m) => (
                <MessageBubble key={m.message_id} message={m} onNavigate={onNavigate} />
              ))}
              {working ? (
                <div className="flex justify-start">
                  <div className="max-w-[95%] flex-1 rounded-xl border border-ink-hairline bg-surface-raised px-4 py-3 shadow-card">
                    <p className="flex items-center gap-2 text-sm text-ink-secondary">
                      <Spinner />{' '}
                      {streamingText || pendingCards.length
                        ? 'Copilot is writing…'
                        : 'Agent executing…'}
                      {pendingIntent ? (
                        <span className="chip-neutral">{pendingIntent}</span>
                      ) : null}
                    </p>
                    {streamingText ? (
                      <p className="mt-2 whitespace-pre-wrap text-sm text-ink-primary">
                        {streamingText}
                      </p>
                    ) : null}
                    {pendingCards.length ? (
                      <div className="mt-3 space-y-2">
                        {pendingCards.map((card, i) => (
                          <CardView key={i} card={card} onNavigate={onNavigate} />
                        ))}
                      </div>
                    ) : null}
                  </div>
                </div>
              ) : null}
              <div ref={bottomRef} />
            </div>
          )}

          <div className="mt-4 border-t border-ink-hairline pt-3">
            <div className="flex items-end gap-2">
              <textarea
                className="field min-h-[44px] flex-1 resize-y"
                rows={2}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={onKeyDown}
                placeholder="Ask about risks, findings, fixes… (Enter to send)"
                disabled={working}
              />
              <button
                type="button"
                className="btn-primary"
                disabled={working || !input.trim()}
                onClick={() => send()}
              >
                {working ? <Spinner /> : <Send className="h-4 w-4" />}
                Send
              </button>
            </div>
            <div className="mt-2">
              <NoUnsafeContent />
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
